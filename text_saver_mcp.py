"""
TextSaver MCP - Claudeでローカルファイルシステムにテキストを保存するためのMCP（Model Context Protocol）サーバー

このスクリプトは、Claudeが自然言語コマンドを通じてローカルファイルシステムにテキストを保存できるようにするためのMCPサーバーを実装します。
MCPとは「Model Context Protocol」の略で、AIモデル（このケースではClaude）がローカル環境のリソースと安全に対話するための標準化されたインターフェースです。

主な機能：
- テキストをローカルファイルに保存
- ファイル名が指定されていない場合の自動タイムスタンプ付きファイル名生成
- セキュリティ機能（ファイル名のバリデーション、サニタイゼーション、サイズ制限など）
- 詳細なエラー処理とロギング

使用方法：
1. このスクリプトを実行してMCPサーバーを起動
2. Claude Desktopアプリを設定してこのMCPサーバーを使用
3. 「このテキストをファイルに保存して」などの自然言語でClaudeにリクエスト
"""

# 必要なライブラリのインポート
from mcp.server.fastmcp import FastMCP  # MCPサーバーを作成するためのメインライブラリ
import time
import signal
import sys
import datetime
import os
import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any, Union

# ロギングの設定 - サーバーの状態とデバッグ情報を記録するために使用
logging.basicConfig(
    level=logging.INFO,  # INFO以上のログレベルを表示
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # タイムスタンプ、ロガー名、レベル、メッセージを含むログフォーマット
    handlers=[logging.StreamHandler()]  # 標準出力にログを出力
)
logger = logging.getLogger("text-saver-mcp")  # このアプリケーション用のロガーを作成

# グローバル設定
MAX_TEXT_SIZE = 10 * 1024 * 1024  # 10MBの最大ファイルサイズ制限（バイト単位）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # スクリプトが配置されているディレクトリの絶対パス
ALLOWED_SAVE_DIR = SCRIPT_DIR  # テキストファイル保存を許可するディレクトリ（デフォルトはスクリプトのディレクトリ）
# 安全なファイル名のパターン - 英数字で始まり、英数字、アンダースコア、ハイフン、ドットのみを含む
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$')

# カスタム例外クラス - エラー処理とデバッグを容易にするため
class TextSaverError(Exception):
    """テキスト保存操作で発生するあらゆる種類のエラーの基本例外クラス"""
    pass

class InvalidFilenameError(TextSaverError):
    """ファイル名が無効または安全でない場合に発生する例外"""
    pass

class TextTooLargeError(TextSaverError):
    """テキストが最大許容サイズを超える場合に発生する例外"""
    pass

# シグナルハンドラ - サーバーを適切にシャットダウンするため
def signal_handler(sig, frame):
    """
    SIGINTやSIGTERMなどのシステムシグナルを処理し、サーバーを正常にシャットダウンします。
    Ctrl+Cを押したときや、システムがプロセスを終了させようとしたときに呼び出されます。
    
    引数:
        sig: 受信したシグナル（SIGINT、SIGTERMなど）
        frame: 現在の実行フレーム（この関数では使用しない）
    """
    logger.info("シグナル %s を受信しました。テキスト保存サーバーを正常にシャットダウンしています...", sig)
    sys.exit(0)  # クリーンな終了コードでプログラムを終了

# シグナルハンドラの登録 - OS終了シグナルを適切に処理するため
signal.signal(signal.SIGINT, signal_handler)   # Ctrl+Cの処理
signal.signal(signal.SIGTERM, signal_handler)  # 終了シグナルの処理

def validate_filename(filename: str) -> bool:
    """
    ファイル名が安全であり、パストラバーサル攻撃が含まれていないことを検証します。
    
    パストラバーサル攻撃とは、ファイルパスを操作して本来アクセスできないはずのディレクトリや
    ファイルにアクセスしようとする攻撃です（例: "../../../etc/passwd"）。
    
    引数:
        filename: 検証するファイル名
        
    戻り値:
        bool: ファイル名が安全な場合はTrue、安全でない場合はFalse
    """
    # パストラバーサル攻撃のチェック - 絶対パスや親ディレクトリの参照を防止
    if os.path.isabs(filename) or '..' in filename or '/' in filename or '\\' in filename:
        return False
        
    # ファイル名が安全なパターンに一致するかチェック - 許可された文字のみを含むことを確認
    return bool(SAFE_FILENAME_PATTERN.match(filename))

def sanitize_path(filename: str) -> str:
    """
    危険な文字を削除し、ファイル名を安全な形式に変換します。
    
    この関数は、validate_filenameで検証に失敗したファイル名を安全な形式に変換します。
    パス成分を削除し、危険な文字をアンダースコアに置き換えます。
    
    引数:
        filename: サニタイズするファイル名
        
    戻り値:
        str: サニタイズされた安全なファイル名
    """
    # パスなしの基本ファイル名を取得 - パス成分を取り除く
    base_filename = os.path.basename(filename)
    
    # 安全でない文字をアンダースコアに置き換える
    # 各文字が安全なパターンに一致する場合はそのまま使用し、そうでない場合は'_'に置き換える
    safe_filename = ''.join(c if SAFE_FILENAME_PATTERN.match(c) else '_' for c in base_filename)
    
    # サニタイズ後にファイル名が空の場合はデフォルトを使用
    if not safe_filename:
        safe_filename = "file.txt"
        
    return safe_filename

# MCPサーバーインスタンスの作成
# FastMCPはmcpライブラリによって提供されるクラスで、MCPサーバーを簡単に作成するためのものです
mcp = FastMCP(
    name="text-saver",     # このMCPサーバーの名前
    host="127.0.0.1",      # ローカルホストにバインド（外部からのアクセスを防止）
    port=8080,             # リッスンするポート番号
    timeout=30             # タイムアウト秒数（リクエスト処理の最大待機時間）
)

# MCPツールの定義
# @mcp.tool()デコレータは、この関数をMCPツールとして登録します
# Claudeはこの関数を、テキストをファイルに保存するためのツールとして呼び出すことができます
@mcp.tool()
def save_text(text: str, filename: Optional[str] = None) -> Union[str, Dict[str, Any]]:
    """
    セキュリティとエラー処理を備えたテキストをファイルに保存します。
    
    このツールは提供されたテキストコンテンツをローカルファイルシステム上のファイルに保存します。
    ファイル名が指定されていない場合、自動的にタイムスタンプ付きのファイル名を生成します。
    
    引数:
        text: ファイルに保存するテキストコンテンツ
        filename: オプションのファイル名。指定されていない場合は、
                 'year-month-date-hour-minute-second.txt'
                 形式のタイムスタンプを使用します
    
    戻り値:
        保存されたファイルへのパスを含む成功メッセージ、またはエラーメッセージ
        
    例外:
        TextTooLargeError: テキストが許容される最大サイズを超える場合
        InvalidFilenameError: 提供されたファイル名が無効または安全でない場合
        IOError: ファイルへの書き込み中に問題が発生した場合
    """
    try:
        # 入力を検証 - textパラメータが文字列であることを確認
        if not isinstance(text, str):
            return {"status": "error", "message": "エラー: テキストは文字列である必要があります"}
            
        # テキストサイズの確認 - 許容される最大サイズを超えていないか
        # UTF-8エンコードされたサイズをバイト単位で確認
        if len(text.encode('utf-8')) > MAX_TEXT_SIZE:
            raise TextTooLargeError(f"テキストサイズが許容される最大値（{MAX_TEXT_SIZE}バイト）を超えています")
            
        # ファイル名の生成または検証
        if not filename:
            # ファイル名が指定されていない場合、現在の日時に基づいたタイムスタンプファイル名を生成
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            filename = timestamp + ".txt"
        else:
            # ファイル名が提供されている場合、安全性を検証
            if not validate_filename(filename):
                logger.warning("安全でないファイル名が試行されました: %s", filename)
                # 安全でないファイル名をサニタイズ
                filename = sanitize_path(filename)
                logger.info("ファイル名をサニタイズしました: %s", filename)
        
        # ファイル名に.txt拡張子があることを確認
        if not filename.endswith('.txt'):
            filename += '.txt'
        
        # 保存ディレクトリが存在しない場合は作成
        Path(ALLOWED_SAVE_DIR).mkdir(parents=True, exist_ok=True)
        
        # 許可されたディレクトリ内の完全なパスを作成
        filepath = os.path.join(ALLOWED_SAVE_DIR, filename)
        
        # 操作をログに記録 - デバッグと監査のため
        logger.info(f"現在の作業ディレクトリ: {os.getcwd()}")
        logger.info(f"スクリプトディレクトリ: {os.path.dirname(os.path.abspath(__file__))}")
        logger.info(f"保存先: {filepath}")
        
        # テキストをファイルに保存
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(text)
        except PermissionError:
            # 書き込み権限がない場合のエラーハンドリング
            return {"status": "error", "message": f"ファイルへの書き込み権限がありません: {filename}"}
        except IOError as e:
            # その他のI/Oエラーのハンドリング
            return {"status": "error", "message": f"ファイルへの書き込み中にIOエラーが発生しました: {str(e)}"}
        
        # ユーザーフィードバックのために絶対パスを取得
        abs_path = os.path.abspath(filepath)
        
        # 検証: ファイルが正常に書き込まれたかチェック
        if not os.path.exists(filepath):
            return {"status": "error", "message": f"ファイルが正常に作成されませんでした: {abs_path}"}
            
        # 検証: ファイルサイズの確認
        file_size = os.path.getsize(filepath)
        if file_size == 0 and len(text) > 0:
            return {"status": "error", "message": f"ファイルは作成されましたが、空のようです: {abs_path}"}
        
        # 成功レスポンスを返す
        return {
            "status": "success", 
            "message": f"テキストをファイルに正常に保存しました: {abs_path}",
            "path": abs_path,  # 保存されたファイルの絶対パス
            "size": file_size, # ファイルサイズ（バイト）
            "filename": filename  # 使用されたファイル名
        }
        
    except TextTooLargeError as e:
        # テキストサイズに関するエラーのハンドリング
        logger.error("テキストサイズエラー: %s", str(e))
        return {"status": "error", "message": str(e)}
    except InvalidFilenameError as e:
        # ファイル名に関するエラーのハンドリング
        logger.error("無効なファイル名エラー: %s", str(e))
        return {"status": "error", "message": str(e)}
    except Exception as e:
        # 予期しないエラーのキャッチオール - 常に安全にエラーを処理
        logger.exception("テキスト保存中に予期しないエラーが発生しました: %s", str(e))
        return {"status": "error", "message": f"予期しないエラー: {str(e)}"}

def main() -> None:
    """
    MCPサーバーのメインエントリーポイント
    
    このスクリプトがコマンドラインから直接実行された場合に呼び出されます。
    MCPサーバーを初期化して起動し、終了処理も行います。
    """
    try:
        # サーバー起動のログ出力
        logger.info("TextSaver MCPサーバー 'text-saver' を 127.0.0.1:8080 で起動しています")
        logger.info("ファイルの保存先ディレクトリ: %s", ALLOWED_SAVE_DIR)
        logger.info("最大許容ファイルサイズ: %d バイト", MAX_TEXT_SIZE)
        
        # 保存ディレクトリが存在することを確認
        Path(ALLOWED_SAVE_DIR).mkdir(parents=True, exist_ok=True)
        
        # MCPサーバーの実行
        # transport='stdio'パラメータは、サーバーが標準入出力を使用してClaudeと通信することを指定
        # これにより、Claude Desktopアプリはこのプロセスと通信できる
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        # Ctrl+Cなどのキーボード割り込みでクリーンアップ
        logger.info("キーボード割り込みを受信しました、シャットダウンしています...")
    except Exception as e:
        # その他の例外のハンドリング
        logger.exception("サーバー起動中にエラーが発生しました: %s", str(e))
        # エラーログが表示される時間を確保するために一時停止
        time.sleep(5)
    finally:
        # 常に実行される終了メッセージ
        logger.info("サーバーのシャットダウンが完了しました")

# スクリプトがコマンドラインから直接実行された場合の処理
if __name__ == "__main__":
    main()  # メイン関数を実行