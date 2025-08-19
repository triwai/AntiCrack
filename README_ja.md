# AntiCrack - EAC スタイル アンチチート保護システム

**Languages / 言語**: [English](README.md) | [日本語](README_ja.md)

AntiCrack は、ゲームやアプリケーションに EAC（Easy Anti-Cheat）レベルのセキュリティを提供するよう設計された高度なリバースエンジニアリング対策およびアンチチート保護システムです。チーターやクラッカーが一般的に使用するデバッグ、メモリ操作、コード改ざん、その他の攻撃ベクターに対する包括的な保護を実装しています。

## 🛡️ 機能

### コア保護メカニズム
- **高度なデバッガー検出**: デバッグツール（x64dbg、OllyDbg、IDA Pro など）の多層検出
- **メモリ保護**: メモリ変更とコードパッチングのリアルタイム監視
- **プロセス整合性**: ロードされたモジュールとプロセス整合性の検証
- **VM 検出**: 解析に使用される仮想マシン環境の検出
- **API フック検出**: API インターセプションと関数フックからの保護
- **ハードウェアブレークポイント検出**: ハードウェアレベルのデバッグ試行の検出
- **タイミング解析**: タイミング異常によるデバッグの検出

### EAC スタイル ゲーム統合
- **必須保護**: AntiCrack がアクティブでないとゲームは実行できません
- **セキュア通信**: 暗号化されたチャレンジ・レスポンス認証
- **相互監視**: AntiCrack とゲームが相互に監視
- **ハートビートシステム**: 継続的な接続検証
- **自動終了**: 保護が侵害された場合、ゲームは終了されます
- **脅威レポート**: 双方向脅威情報共有

### 高度なセキュリティ機能
- **暗号化保護**: 機密操作のための AES 暗号化
- **ランタイムトークン検証**: セキュアなトークンベース認証
- **プロセスホワイトリスト**: 認可されたゲームのみが接続可能
- **チャレンジ・レスポンス認証**: 不正なゲーム登録を防止
- **接続整合性**: 通信チャンネルの継続的監視

## 🚀 クイックスタート

### 前提条件
- Java 8 以上
- Gradle（ソースからビルドする場合）

### AntiCrack 保護システムの実行

1. **AntiCrack サービスの開始**:
   ```bash
   java -cp build/classes/java/main dev.anticrack.Main
   ```

2. **サービスは自動的に**:
   - すべての保護メカニズムを初期化
   - ポート 25565 でゲーム統合サービスを開始
   - 脅威の監視を開始
   - ゲームの接続を待機

3. **出力例**:
   ```
   === AntiCrack Protection System v1.0.0 ===
   高度なリバースエンジニアリング保護を初期化中...
   [AntiCrack] 保護システムを開始中...
   [AntiCrack] デバッガー検出を開始中...
   [AntiCrack] メモリ保護を開始中...
   [AntiCrack] プロセス整合性チェックを開始中...
   [AntiCrack] 仮想マシン検出を開始中...
   [AntiCrack] EAC スタイル ゲーム統合サービスを開始中...
   [GameIntegration] サービスがポート 25565 で開始されました
   [AntiCrack] すべての保護システムが正常に開始されました
   AntiCrack 保護がアクティブになり、脅威を監視しています。
   ```

### サンプルゲームクライアントの実行

1. **サンプルゲームの開始**（AntiCrack が先に実行されている必要があります）:
   ```bash
   java -cp build/classes/java/main dev.anticrack.examples.SampleGameClient
   ```

2. **ゲームは次のことを行います**:
   - AntiCrack が実行されているかチェック
   - AntiCrack に登録し認証
   - 保護されたゲームプレイを開始
   - ハートビート通信を維持
   - 保護が失われた場合は終了

## 🎮 ゲーム統合ガイド

### 統合概要

ゲームは実行するために AntiCrack と統合する必要があります。統合プロセスは以下のステップに従います：

1. **可用性チェック**: AntiCrack サービスが実行されているか確認
2. **登録**: ゲーム情報を送信し登録を要求
3. **認証**: チャレンジ・レスポンス認証を完了
4. **通信**: ハートビートとステータス通信を維持
5. **監視**: AntiCrack の可用性を監視し脅威に対応

### ステップ別統合

#### ステップ 1: AntiCrack の可用性チェック

```java
private boolean checkAntiCrackAvailability() {
    try (Socket testSocket = new Socket()) {
        testSocket.connect(new InetSocketAddress("localhost", 25565), 5000);
        System.out.println("AntiCrack サービスが検出され利用可能です");
        return true;
    } catch (IOException e) {
        System.err.println("AntiCrack サービスが利用できません - ゲームを開始できません！");
        return false;
    }
}
```

#### ステップ 2: AntiCrack への登録

```java
// AntiCrack サービスに接続
Socket socket = new Socket("localhost", 25565);
BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

// 登録要求を送信
String registrationRequest = "REGISTER:YourGameName:1.0.0:GAME_SIGNATURE";
writer.println(registrationRequest);

// レスポンスを処理
String response = reader.readLine();
if (response.startsWith("CHALLENGE:")) {
    String challengeData = response.substring(10);
    // 認証に進む
}
```

#### ステップ 3: 認証チャレンジの処理

```java
private boolean handleAuthenticationChallenge(String challengeData) {
    // 本番環境では、AntiCrack の CryptoProtection に合わせた適切な AES 暗号化を使用
    // デモでは、"ENCRYPTED:" + challengeData の Base64 エンコーディングを使用
    String challengeResponse = Base64.getEncoder()
        .encodeToString(("ENCRYPTED:" + challengeData).getBytes());
    
    writer.println(challengeResponse);
    
    String authResult = reader.readLine();
    if (authResult.startsWith("SUCCESS:")) {
        String authToken = authResult.substring(8);
        // 認証成功 - ゲーム開始
        return true;
    }
    return false;
}
```

#### ステップ 4: ハートビートシステムの実装

```java
// 4秒ごとにハートビートを送信（15秒タイムアウトより速い）
ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
executor.scheduleAtFixedRate(() -> {
    if (connected.get() && gameRunning.get()) {
        writer.println("HEARTBEAT:" + System.currentTimeMillis());
    }
}, 1000, 4000, TimeUnit.MILLISECONDS);
```

#### ステップ 5: AntiCrack メッセージの監視

```java
// AntiCrack からのメッセージを監視
executor.submit(() -> {
    try {
        String message;
        while (connected.get() && (message = reader.readLine()) != null) {
            if (message.equals("ACK")) {
                // ハートビート確認
            } else if (message.startsWith("TERMINATE:")) {
                String reason = message.substring(10);
                System.err.println("AntiCrack が終了を要求しました: " + reason);
                // セキュリティのため即座に終了する必要があります
                System.exit(3);
            }
        }
    } catch (IOException e) {
        // 接続が失われました - 終了する必要があります
        System.err.println("AntiCrack への接続が失われました - セキュリティのため終了します");
        System.exit(2);
    }
});
```

#### ステップ 6: ゲームステータスと脅威の報告

```java
// 定期的にゲームステータスを報告
writer.println("STATUS:正常に実行中 - レベル 5");

// 検出された脅威を報告
writer.println("THREAT:疑わしいメモリアクセスパターンが検出されました");
```

## 🔧 API リファレンス

### 通信プロトコル

AntiCrack はポート 25565 での TCP ソケット通信を使用してテキストベースのプロトコルを使用します。

#### ゲーム → AntiCrack メッセージ

| メッセージ形式 | 説明 | 例 |
|---|---|---|
| `REGISTER:name:version:signature` | ゲームを AntiCrack に登録 | `REGISTER:MyGame:1.2.0:ABC123` |
| `HEARTBEAT:timestamp` | 接続を維持するためのハートビート送信 | `HEARTBEAT:1634567890123` |
| `STATUS:description` | 現在のゲームステータスを報告 | `STATUS:正常に実行中 - レベル 3` |
| `THREAT:description` | 検出された脅威を報告 | `THREAT:メモリスキャナーが検出されました` |

#### AntiCrack → ゲーム メッセージ

| メッセージ形式 | 説明 | 必要なアクション |
|---|---|---|
| `CHALLENGE:data` | 認証チャレンジ | データを暗号化して応答 |
| `SUCCESS:token` | 認証成功 | トークンを保存して続行 |
| `ERROR:reason` | 要求失敗 | エラーを処理し、必要に応じて終了 |
| `ACK` | ハートビート確認 | 通常の動作を継続 |
| `TERMINATE:reason` | 強制終了 | 即座にアプリケーションを終了 |

### 保護レベル

AntiCrack は設定可能な保護レベルをサポートしています：

- **LOW**: 最小限のパフォーマンス影響でのベーシック脅威検出
- **MEDIUM**: セキュリティ/パフォーマンスのバランスが取れた標準保護
- **HIGH**: アクティブな対抗措置を伴う包括的保護
- **MAXIMUM**: すべての保護メカニズムが有効 - 最高セキュリティ
- **CUSTOM**: ユーザー定義の保護設定

### 脅威タイプ

システムは様々な脅威タイプを検出し報告できます：

- `DEBUGGER_DETECTED`: デバッグツールが検出されました
- `MEMORY_PATCHING`: メモリ変更の試行
- `PROCESS_INJECTION`: プロセスまたは DLL インジェクション
- `VIRTUAL_MACHINE`: VM 環境が検出されました
- `API_HOOKING`: API インターセプションが検出されました
- `HARDWARE_BREAKPOINT`: ハードウェアデバッグが検出されました
- `TIMING_ANOMALY`: 疑わしいタイミングパターン
- `CODE_INTEGRITY_VIOLATION`: コード改ざんが検出されました
- `UNKNOWN_THREAT`: 未分類のセキュリティ脅威

## 🏗️ ソースからのビルド

### 前提条件
- JDK 8+
- Gradle 6.0+

### ビルドコマンド

```bash
# リポジトリをクローン
git clone <repository-url>
cd AntiCrack

# プロジェクトをビルド
gradle build

# テストを実行
gradle test

# 配布用パッケージを作成
gradle distZip
```

### プロジェクト構造

```
AntiCrack/
├── src/main/java/dev/anticrack/
│   ├── AntiCrack.java              # コア保護システム
│   ├── AntiCrackAPI.java           # パブリック API インターフェース
│   ├── GameIntegrationService.java # EAC スタイル ゲーム統合
│   ├── CryptoProtection.java       # 暗号化ユーティリティ
│   ├── ThreatType.java             # 脅威列挙型
│   ├── ProtectionLevel.java        # 保護レベル設定
│   ├── ThreatCallback.java         # 脅威通知インターフェース
│   ├── Main.java                   # アプリケーションエントリーポイント
│   └── examples/
│       └── SampleGameClient.java   # ゲーム統合の例
├── build.gradle                    # ビルド設定
├── settings.gradle                 # Gradle 設定
└── README.md                       # このファイル
```

## ⚙️ 設定

### 保護レベル設定

```java
AntiCrackAPI api = AntiCrackAPI.getInstance();
api.setProtectionLevel(ProtectionLevel.HIGH);
```

### カスタム脅威コールバック

```java
api.setThreatCallback(new ThreatCallback() {
    @Override
    public void onThreatDetected(ThreatType type, String description) {
        System.err.println("セキュリティ警告: " + type + " - " + description);
        // カスタムレスポンスを実装（ログ記録、ネットワーク通知など）
    }
    
    @Override
    public void onThreatMitigated(ThreatType type, String description) {
        System.out.println("脅威が軽減されました: " + description);
    }
});
```

## 🔒 セキュリティに関する考慮事項

### ゲーム開発者向け

1. **AntiCrack チェックをバイパスしない** - ゲーム開始前に常に AntiCrack が実行されていることを確認
2. **接続失敗を即座に処理** - AntiCrack 接続が失われた場合はゲームを終了
3. **適切な暗号化を実装** - 本番環境では AntiCrack と同じ暗号化手法を使用
4. **継続的に監視** - ゲームプレイ中は AntiCrack とのアクティブな通信を維持
5. **脅威を報告** - ゲームで検出された疑わしい活動を AntiCrack に通知

### 本番環境デプロイ

1. **強力な暗号化キーを使用** - デモ暗号化を本番グレードのキーに置き換え
2. **証明書検証を実装** - 登録を許可する前にゲーム署名を検証
3. **適切な保護レベルを設定** - セキュリティニーズとパフォーマンス要件のバランスを取る
4. **ログを積極的に監視** - 脅威検出イベントの監視を設定
5. **定期的に更新** - 新しい攻撃ベクターから保護するために AntiCrack を最新に保つ

## 🚨 トラブルシューティング

### よくある問題

#### ゲームが AntiCrack に接続できない
- AntiCrack が実行されてポート 25565 でリスニングしていることを確認
- ファイアウォール設定でポート 25565 への接続が許可されていることを確認
- 他のアプリケーションがポート 25565 を使用していないことを確認

#### 認証失敗
- 暗号化実装が AntiCrack の期待値と一致することを確認
- チャレンジレスポンスが 30 秒のタイムアウト内に送信されることを確認
- デモ実装では適切な Base64 エンコーディングを確認

#### 接続タイムアウト
- ハートビートが 4 秒以下で送信されることを確認
- ゲームと AntiCrack 間のネットワーク安定性を確認
- ゲームが ACK レスポンスを適切に処理することを確認

#### 誤脅威検出
- 保護レベル設定を確認（過度に積極的な場合は下げることを検討）
- 検出をトリガーする可能性のある正当なツールを確認
- 脅威コールバックでの適切な例外処理を実装

### デバッグモード

トラブルシューティングのために詳細ログを有効にする：

```java
System.setProperty("anticrack.debug", "true");
```

## 📝 ライセンス

このプロジェクトは EAC スタイルアンチチート保護の実装例として提供されています。

## 🤝 貢献

貢献を歓迎します！すべてのセキュリティ改善が既存のゲーム統合との後方互換性を維持することを確認してください。

## 📞 サポート

技術サポートと統合支援については、この README で提供されている実装例と API ドキュメントを参照してください。

---

**⚠️ セキュリティ通知**: この保護システムは堅牢に設計されていますが、どのアンチチートシステムも 100% 破られないものではありません。セキュリティ効果を維持するためには継続的な更新と監視が不可欠です。


# あなた専用のアンチチートまたはアンチクラックを作成する必要がある場合は、DISCORD で@thisistriwaiへフレンド申請をしてください
