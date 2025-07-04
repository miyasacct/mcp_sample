# TextSaver MCP

ローカルファイルシステムにテキストを保存できるようにする、Claude MCP（Model Context Protocol）サーバーです。

## 機能

- 📝 シンプルなコマンドでテキスト入力をファイルに保存
- 🕒 ファイル名が指定されていない場合、自動的にタイムスタンプ付きのファイル名を生成
- 🔒 ファイル名の検証とサニタイズによる組み込みセキュリティ
- 🚫 ディレクトリトラバーサル攻撃からの保護
- ⚠️ 包括的なエラー処理とロギング
- ✅ ファイルシステムの乱用を防ぐサイズ制限保護

## インストール

### 前提条件

- Python 3.8以上
- Claude Desktopアプリケーション

### セットアップ

1. このリポジトリをクローンします。

2. 必要な依存関係をインストールします:
   ```bash
   pip install -r requirements.txt
   ```

3. Claude DesktopでMCPサーバーを使用するよう設定します（macOS）:
   1. **Claude Desktop アプリを起動**:
      - アプリケーションフォルダから Claude を起動します。
   2. **メニューバーから「Settings…」を開く**:
      - 画面上部のメニューバーで「Claude」→「Settings…」を選択します。  
      - ※アプリウィンドウ内の「Settings」ではなく、メニューバーの「Settings…」を選んでください。
   3. **「Developer」タブを開く**:
      - 左側のサイドバーから「Developer」タブを選択します。
   4. **「Edit Config」をクリック**:
      - 「Edit Config」ボタンをクリックすると、`claude_desktop_config.json` ファイルが作成され、デフォルトのテキストエディタで開かれます。

      - Claude Desktop設定ファイルを開く:
        - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

   以下の設定を追加:
   ```json
   {
     "mcpServers": {
       "text-saver": {
         "command": "/opt/homebrew/bin/python3", // 例)環境をhomebrewで作成
         "args": [
           "/{fullpath}/mcp_sample/text_saver_mcp.py" // プロジェクト内のメインプログラムまでのpathを記載
         ],
         "cwd": "/{fullpath}/mcp_sample", // プロジェクトまでのpathを記載
         "host": "127.0.0.1",
         "port": 8080,
         "timeout": 30000
       }
     }
   }
   ```
   
   パスをシステム上の実際の場所に置き換えてください。

1. Claude Desktopを再起動

## 使用方法

設定が完了したら、自然言語を使用してClaudeにテキストをファイルに保存するよう依頼できます:

- 「このテキストをファイルに保存して」
- 「この情報をnotes.txtというファイルに保存して」
- 「このコンテンツをproject-ideas.txtという名前のテキストファイルに書き込んで」

テキストは設定で指定されたディレクトリに保存されます。

## セキュリティ機能

- **ファイルサイズ制限**: 過度に大きなファイルの保存を防止（デフォルト: 10MB）
- **ファイル名の検証**: ファイル名が安全でパストラバーサルの試みを含まないことを確認
- **サニタイズ**: 安全でないファイル名を自動的にサニタイズ
- **パス制御**: ファイルは指定されたディレクトリにのみ保存可能

## トラブルシューティング

### 一般的な問題

#### "spawn python ENOENT" エラー
このエラーはClaudeがPython実行ファイルを見つけられないことを意味します。設定ファイルでPythonインタープリタへのフルパスを使用してください:

```bash
# Pythonパスを見つける
which python

# そのパスを設定で使用
```

#### "Read-only file system" エラー
これはスクリプトが指定されたディレクトリに書き込む権限がないことを意味します。スクリプトまたは設定で書き込み可能なディレクトリが設定されていることを確認してください。

#### 権限の問題
ファイルを保存するディレクトリに適切な書き込み権限があることを確認してください:

```bash
chmod 755 /path/to/save/directory
```

### デバッグ

スクリプトには問題診断に役立つ詳細なロギングが含まれています。Claude Desktopの開発者コンソールでログを確認してください。

### MCP初心者向けの説明:Claudeからこのテキスト保存MCPを呼び出す場合の実行フローについて

  1. 最初の実行：main()関数
    - スクリプト起動時にmain()関数が実行され、MCPサーバーが初期化されます。
    - これはMCPサーバーの起動段階で、Claudeからの呼び出しの前に行われます。
    - mcp.run(transport='stdio')がサーバーを起動し、標準入出力を通じてClaudeと通信できるようにします。
  2. Claudeからの呼び出し時：save_text()関数
    - ユーザーがClaudeに「このテキストをファイルに保存して」などと依頼すると、Claudeはsave_text()関数を呼び出します。
    - この関数は@mcp.tool()デコレータによってMCPツールとして登録されています。
    - 呼び出し時には通常2つのパラメータが渡されます：
        - text: 保存するテキスト（必須）
      - filename: ファイル名（オプション、指定されていない場合はタイムスタンプで自動生成）
  3. 処理の流れ：
    - テキストタイプの検証（文字列であることを確認）
    - テキストサイズの確認（10MB以下であることを確認）
    - ファイル名の処理（生成または検証・サニタイズ）
    - ファイルへの書き込み
    - 成功または失敗のレスポンスの返却
