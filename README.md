# tunnneji-tail (English)
Want to access a specific local app remotely, or share a single service with a friend, but feel that installing a full-system VPN is overkill?

You have been conditioned to think that joining a "VPN" inherently means securely bridging your entire operating system to another network. Aren't you? But fundamentally, a VPN is just encrypted traffic. There is no technical rule stating your *entire* machine needs to join a network just to share or access a single port.

## A Userspace, Zero-Trust Tunnel
**`tunnneji-tail`** is a standalone, portable Tailscale client implementation inspired by `wstunnel`.
Instead of hooking into your OS routing tables or creating virtual network adapters, this single binary handles the entire VPN lifecycle in userspace. It isolates the VPN traffic and maps it strictly to specific `localhost` ports. It feels exactly like SSH local/remote port forwarding, but backed by Tailscale's resilient, decentralized mesh network.

### Core Concepts
* **Hostile by Default (The "Untrusted" VPN):** Traditional VPNs imply trust among participants. We assume the opposite: the VPN is a hostile environment, potentially filled with attackers or subject to man-in-the-middle risks (especially when relying on external coordination servers).. There is no DNS, and by default, your machine is invisible. You only expose exactly what you choose to map, completely neutralizing the fear of giving someone full network access to your PC.
Because we treat the VPN with absolute zero-trust, we achieve a highly unconventional way to manage networks. You can securely invite completely unrelated groups—like your high school friends and your college friends—into the *exact same* VPN. By applying port-specific encryption passwords (`-P1a`, `-P1b`), neither group can access the other's services. Grouping everyone into one VPN safely reduces network overhead (like keep-alive packets) and improves efficiency compared to running multiple separate VPNs.
* **App-Layer Encryption (`-P`):** Add ChaCha20 encryption directly on top of the VPN tunnel. You can share access securely without trusting the underlying network peers. (If you *do* trust the network, simply omit this option).
* **Total Stealth Mode:** If all the ports you are sharing are password-protected, or if you are only acting as a client (sharing no ports), `tunnneji-tail` silently drops all ICMP ping requests. To the rest of the VPN, your machine does not even exist.
* **No Root, No System Changes:** Runs entirely in userspace. Your overall OS network stack remains completely untouched.

## Step-by-Step Guide
### 1. Basic Sharing (Person A)
Person A wants to share their local web server (running on port `443`) to the VPN.
```bash
./tunnneji-tail -S 443:localhost:443 -K <apikey>
```

**Shorthand form:** If your local target port is the same as the VPN listen port, you can omit it.
```bash
./tunnneji-tail -S 443:localhost -K <apikey>
```

**Subsequent connections:** After the first run, a `tailscaled.state` file is generated. You no longer need your API key!
```bash
./tunnneji-tail -S 443:localhost
```

> **Note:** If you want to read/write the state file to a specific location instead of the default, use the `-T <filepath>` option.

### 2. Accessing the Share (Person B)
Person B wants to access Person A's shared server. They map Person A's VPN IP and port (`443`) to their own local port (`10443`).
```bash
./tunnneji-tail -C 10443:<Person_A_IP>:443 -K <apikey>
```
Now, Person B simply opens their browser to `localhost:10443`, and they are securely accessing Person A's server.

### 3. Connecting to Multiple VPNs at Once
If you need to connect to two separate VPNs simultaneously, group your connections by assigning numbers (`1`, `2`, etc.).
```bash
./tunnneji-tail -S1 443:localhost -S1 8080:localhost:80 -K1 <apikey1> -T1 1.state -S2 10443:localhost:443 -K2 <apikey2> -T2 2.state -P2 mypassword
```
* **VPN Group 1:** Shares local port `443` as VPN port `443`, and local port `80` as VPN port `8080` (unencrypted).
* **VPN Group 2:** Shares local port `443` as VPN port `10443`, but encrypts the traffic using the password `mypassword`.

### 4. Port-Specific Passwords
You can slice your permissions even further by assigning lowercase letters (`a`, `b`, etc.) to distinct port groups within the same VPN.
```bash
./tunnneji-tail -S1a 443:localhost -S1b 8080:localhost:80 -K1 <apikey1> -T1 1.state -PS1b 8080pass -S2 10443:localhost:443 -K2 <apikey2> -T2 2.state -P2 mypassword
```
* In **VPN Group 1**, port `443` (`a`) is shared normally, but port `8080` (`b`) requires the password `8080pass` to access.
* **VPN Group 2** operates with its own global password as defined before.

---

## Advanced Specifications

### The Equivalence of `-S` (Server) and `-C` (Client)
`-S` and `-C` are fundamentally just different directions for NAT (port forwarding) and passwords.

* `-S` means **"Listen on the VPN side, dial out to the local side."**
* `-C` means **"Listen on the local side, dial out to the VPN side."**

Their internal processing is completely equivalent, and port group identifiers like `-S1a` or `-C1a` can be applied to both in exactly the same way.
(However, there is one key difference: the stealth mode decision—whether to ignore ICMP ping requests—only considers the state of the `-PS` side, i.e., whether ports exposed to the VPN are password-protected.)

### Differences in Rules: Password (`-P`) vs. IP Whitelist (`-A`)
* **Password (`-P`) can omit the direction:**
  When specified alone (like `-P mypassword` or `-P1 mypassword`), the password is automatically applied to **both directions** (`-S` and `-C`). This is because it's common to use the same password for both inbound and outbound connections.
* **IP Whitelist (`-A`) REQUIRES a direction:**
  In addition to passwords, you can protect connections using an IP whitelist to restrict access to specific IP addresses (if omitted, all IPs are allowed). However, specifying a standalone `-A 127.0.0.1` or `-A1 100.64.0.1` will result in an error.
  This is because the IP address space inside the VPN (e.g., `100.64.0.0/10`) is entirely different from your local network's IP address space (e.g., `127.0.0.1`). Therefore, you **must explicitly state** which direction you are restricting by using `-AS` (restricting access from the VPN space) or `-AC` (restricting access from the local space).
  * Example: `-AC 127.0.0.1` (Allow access only from your own local PC)
  * Example: `-AS1a 100.64.0.0/10` (Allow access only from a specific subnet within VPN group 1, port group 'a')
  *Note: You can specify multiple IPs by joining them with an underscore `_` (e.g., `-AS 100.64.0.1_100.64.0.2`).*

## Build Instructions
You can build the binary directly using Go. No external build scripts are required.

### Release Build (Recommended)
Strips debug symbols and source paths to minimize binary size.
```bash
go build -trimpath -tags "ts_omit_systray,ts_omit_webclient,ts_omit_webbrowser,ts_omit_qrcodes,ts_omit_colorable,ts_omit_desktop_sessions,ts_omit_completion,ts_omit_completion_scripts,ts_omit_drive" -ldflags="-s -w" -o tunnneji-tail ./cmd/tunnneji-tail
```

### Cross-platform Build
Since the build tags are quite long, it is recommended to assign them to a variable before setting `GOOS` and `GOARCH`.

```bash
TAGS="ts_omit_systray,ts_omit_webclient,ts_omit_webbrowser,ts_omit_qrcodes,ts_omit_colorable,ts_omit_desktop_sessions,ts_omit_completion,ts_omit_completion_scripts,ts_omit_drive"

# Linux (amd64 / arm64)
GOOS=linux GOARCH=amd64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-linux-amd64 ./cmd/tunnneji-tail
GOOS=linux GOARCH=arm64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-linux-arm64 ./cmd/tunnneji-tail

# macOS (Intel / Apple Silicon)
GOOS=darwin GOARCH=amd64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-darwin-amd64 ./cmd/tunnneji-tail
GOOS=darwin GOARCH=arm64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-darwin-arm64 ./cmd/tunnneji-tail

# Windows (amd64 / arm64)
GOOS=windows GOARCH=amd64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-windows-amd64.exe ./cmd/tunnneji-tail
GOOS=windows GOARCH=arm64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-windows-arm64.exe ./cmd/tunnneji-tail
```

### Windows (MSVC/CGO and Icon Embedding)
If you need CGO support or want to embed Windows-specific metadata (like an application icon), build as follows:
1. Ensure a C compiler (GCC/MinGW or MSVC) is in your `PATH`.
2. Generate a resource file for the icon or manifest using `rsrc`:
	```bash
	go install github.com/akavel/rsrc@latest
	rsrc -manifest app.manifest -ico app.ico -o rsrc.syso
	```
3. Build the binary with the generated resource file:
	```bash
	TAGS="ts_omit_systray,ts_omit_webclient,ts_omit_webbrowser,ts_omit_qrcodes,ts_omit_colorable,ts_omit_desktop_sessions,ts_omit_completion,ts_omit_completion_scripts,ts_omit_drive"
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail.exe ./cmd/tunnneji-tail
	```

---

## License
This repository is provided under multiple licenses to clearly distinguish the original application logic from the underlying network engine.

* **Original Application (AGPL-3.0):**
  All code under the `cmd/tunnneji-tail/` directory, including the CLI parser, port-forwarding logic, ChaCha20 encryption hooks, and the overall zero-trust concept, are licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. (See the `LICENSE` file for details).

* **Network Engine (BSD-3-Clause):**
  This project builds upon the robust networking engine originally developed by Tailscale. All code outside of the `cmd/tunnneji-tail/` directory (including WireGuard implementations, NAT traversal, and userspace networking stacks) is governed by the original **BSD 3-Clause License** from Tailscale Inc. and contributors. (See the `LICENSE-Tailscale` file for details).

---

# tunnneji-tail (日本語)
外出先から自宅のPCの特定のアプリにアクセスしたり、ローカルで動いているサービスを友人に共有したい。でも、そのためだけにパソコン全体をVPNに参加させたり、OSのネットワーク設定をいじるのは少しやりすぎに感じませんか？

皆さんは普段、「VPNを導入する＝パソコン全体を別のネットワークに繋ぎ合わせるもの」と思い込んでいませんか？しかし、それらは単なる規格であり、ネットワークの根底にあるのは、ただのパケットのやり取りに過ぎません。特定のポートにアクセスしたいだけなのに、わざわざOS全体を巻き込む必要はどこにもないのです。

## ユーザースペースで動くゼロトラスト・トンネル
**`tunnneji-tail`** は、`wstunnel`からインスピレーションを受けて開発された、Tailscaleの独立したクライアント実装です。
OSのネットワーク環境（ルーティングテーブルや仮想NIC）を一切汚さず、このアプリ単体がユーザースペースでVPN処理を完結させます。通信結果は `localhost` の特定のポートに直接マッピングされるため、まるで **「強力なメッシュネットワークを使ったSSHポートフォワーディング」** のような感覚で手軽に利用できます。

### コンセプトと強み
* **四面楚歌なVPN:** 従来のVPNは「参加者＝信頼できる仲間」が前提ですが、このツールではVPN内部をゼロトラストに扱います。外部のTailscaleサーバーを借りて調整を行う以上、中間者攻撃のリスクもゼロではないからです。DNSによる名前解決すらなく、あなたが明示的に設定しない限り、ネットワーク内からあなたのPCに触れることはできません。「誰かをVPNに招待したら、PC全体を見られてしまうのでは？」という心配は無用です。
この極端なゼロトラスト設計により、**全く新しいマルチテナント運用**が可能になります。例えば「高校の友達」と「大学の友達」という全く無関係なグループを、**同じ1つのVPN**に招待してしまって問題ありません。ポートごとに別のパスワード (`-P1a`, `-P1b`) を設定できるため、パスワードを知らなければお互いの環境にはアクセスできないからです。安全性を担保したまま1つのVPNに全員を同居させることで、VPNの生存確認パケット（キープアライブ）などが減り、複数VPNを立ち上げるよりも通信が大幅に効率化されます。これは非常に特殊で強力なVPNの運用方法です。
* **アプリケーション層での暗号化 (`-P`):** 共有する通信内容をChaCha20アルゴリズムでさらに暗号化できます。VPN自体を信用しなくても安全にやり取りが可能です。（信頼できる身内だけのVPNなら、このオプションを外して手軽に共有することもできます）。
* **完全なステルスモード:** 共有する全ポートがパスワードで保護されている場合、または共有するポートが一つもない（クライアント* **環境を汚さない (No Root):** 管理者権限は不要です。既存のネットワーク環境には一切影響を与えません。
としての利用のみ）場合、このツールはICMP ping要求を完全に無視します。VPN内からは、あなたのマシンの存在すら見えなくなります。

## 使い方（ステップバイステップ）
### 1. 基本の共有（共有元: Aさん）
Aさんが、VPN内の自分のIPアドレスの443ポートに、自分のパソコンで動いている `localhost:443` ポートのWebサーバーをに共有したい場合。
```bash
./tunnneji-tail -S 443:localhost:443 -K <apikey>
```

**省略記法:** ローカルのポート番号が共有先のポート番号と同じで良い場合は、後ろを省略できます。
```bash
./tunnneji-tail -S 443:localhost -K <apikey>
```

**2回目以降の起動:** 一度実行すると `tailscaled.state` という状態ファイルが生成されるため、以降はAPIキー（`-K`）の入力が不要になります。
```bash
./tunnneji-tail -S 443:localhost
```

> **メモ:** `tailscaled.state` 以外の場所に状態ファイルを保存・読み込みしたい場合は、`-T <ファイルパス>` オプションを使って指定します。

### 2. 共有されたサーバーを見る（アクセス側: Bさん）
Bさんが、Aさんの共有したサーバー（ポート `443`）を見に行きたい場合。Bさんは、AさんのVPN IPとポートを、自分のローカルポート（ここでは `10443`）にマッピングします。
```bash
./tunnneji-tail -C 10443:<AさんのIP>:443 -K <apikey>
```
これで、Bさんは自分のブラウザで `localhost:10443` にアクセスするだけで、安全にAさんのサーバーへ繋がります。

### 3. 複数のVPNに同時接続する
複数の組織に参加していて、2つの異なるVPNに同時につなぎたい場合は、オプションに番号（グループ番号）を振るだけで解決します。
```bash
./tunnneji-tail -S1 443:localhost -S1 8080:localhost:80 -K1 <apikey1> -T1 1.state -S2 10443:localhost:443 -K2 <apikey2> -T2 2.state -P2 mypassword
```
* **VPN1つ目 (`1`):** ローカルの `80` をVPNの `8080` として、ローカルの `443` をVPNの `443` としてそのまま共有します。
* **VPN2つ目 (`2`):** ローカルの `443` をVPNの `10443` として共有しますが、通信は `mypassword` というパスワードで暗号化されます。

### 4. ポートごとにパスワードを分ける
さらに細かく、同じVPN内でもポートごとにパスワードを分けたい場合は、アルファベットの小文字（サブ識別子）をつけて区別します。
```bash
./tunnneji-tail -S1a 443:localhost -S1b 8080:localhost:80 -K1 <apikey1> -T1 1.state -PS1b 8080pass -S2 10443:localhost:443 -K2 <apikey2> -T2 2.state -P2 mypassword
```
* これで、VPN1つ目の `8080` ポート（共有元はローカルの `80`）へのアクセスだけが `8080pass` で暗号化され、別の権限として保護されるようになります。

---

## 仕様の補足
### `-S` (Server) と `-C` (Client) の対等性
`-S` と `-C` は、どちらも単なるNAT（ポートフォワーディング）やパスワードの方向の違いに過ぎません。

* `-S` は **「VPN側で拾い上げ、ローカル側で発信する」**
* `-C` は **「ローカル側で拾い上げ、VPN側で発信する」**

内部的な処理は完全に対等であり、`-S1a` や `-C1a` のようにポートグループ識別子も全く同じように適用できます。
（ただし、ping要求を無視するかどうかの判定は`-PS` 側（VPN側にパスワード付きで発信する設定）だけが考慮されます）

### パスワード (`-P`) と IPホワイトリスト (`-A`) の指定ルールの違い
* **パスワード (`-P`) は方向指定を省略可能:**
	`-P mypassword` や `-P1 mypassword` のように単体で指定した場合、それは両方向（`-S` と `-C` の両方）に適用されます。行きと帰りで同じパスワードを使い回すことがあるからです。
* **IPホワイトリスト (`-A`) は方向指定が必須:**
	接続の保護機能として、パスワード保護以外に特定のIPアドレスからのアクセスのみを許可するホワイトリスト機能があります（指定しなければ全許可）。ただし、`-A 127.0.0.1`、`-A1 100.64.0.1` のように単体で指定することはできず、エラーになります。
	これは、VPN内部のIPアドレス空間（例: `100.64.0.0/10`）と、ローカルのIPアドレス空間（例: `127.0.0.1`）が異なるためです。そのため、`-AS`（VPN空間からのアクセスを制限）または `-AC`（ローカル空間からのアクセスを制限）のように、どちらの方向に対する制限なのかを明示してください。
	* 例: `-AC 127.0.0.1` (自分のPCのローカルアクセスからのみ許可)
	* 例: `-AS1a 100.64.0.0/10` (番号1のVPNのポートグループaに対して、VPN内の特定のサブネットからのみ許可)
	※アンダースコア `_` を使って複数のIPを繋げることも可能です（例: `-AS 100.64.0.1_100.64.0.2`）。

## ビルド方法
Go言語の環境があれば、外部スクリプトなしで直接ビルド可能です。
### リリースビルド（推奨）

デバッグシンボル等を削除してバイナリサイズを最小化します。
```bash
go build -trimpath -tags "ts_omit_systray,ts_omit_webclient,ts_omit_webbrowser,ts_omit_qrcodes,ts_omit_colorable,ts_omit_desktop_sessions,ts_omit_completion,ts_omit_completion_scripts,ts_omit_drive" -ldflags="-s -w" -o tunnneji-tail ./cmd/tunnneji-tail
```

### クロスコンパイル
ビルドタグが長いため、変数にまとめてから `GOOS` と `GOARCH` を指定してビルドします。

```bash
TAGS="ts_omit_systray,ts_omit_webclient,ts_omit_webbrowser,ts_omit_qrcodes,ts_omit_colorable,ts_omit_desktop_sessions,ts_omit_completion,ts_omit_completion_scripts,ts_omit_drive"

# Linux (amd64 / arm64)
GOOS=linux GOARCH=amd64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-linux-amd64 ./cmd/tunnneji-tail
GOOS=linux GOARCH=arm64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-linux-arm64 ./cmd/tunnneji-tail

# macOS (Intel / Apple Silicon)
GOOS=darwin GOARCH=amd64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-darwin-amd64 ./cmd/tunnneji-tail
GOOS=darwin GOARCH=arm64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-darwin-arm64 ./cmd/tunnneji-tail

# Windows (amd64 / arm64)
GOOS=windows GOARCH=amd64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-windows-amd64.exe ./cmd/tunnneji-tail
GOOS=windows GOARCH=arm64 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail-windows-arm64.exe ./cmd/tunnneji-tail
```

### Windows (MSVC/CGO とアイコンの埋め込み)
CGOのサポートが必要な場合や、Windows固有のメタデータ（アプリアイコンなど）を埋め込む場合は以下のようにビルドします。
1. GCC/MinGW または MSVC が `PATH` に通っていることを確認します。
2. `rsrc` を使ってアイコンやマニフェストをリソースファイルとして生成します。
	```bash
	go install github.com/akavel/rsrc@latest
	rsrc -manifest app.manifest -ico app.ico -o rsrc.syso
	```
3. 生成されたリソースファイルと共にビルドします。
	```bash
	TAGS="ts_omit_systray,ts_omit_webclient,ts_omit_webbrowser,ts_omit_qrcodes,ts_omit_colorable,ts_omit_desktop_sessions,ts_omit_completion,ts_omit_completion_scripts,ts_omit_drive"
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -tags "$TAGS" -ldflags="-s -w" -o tunnneji-tail.exe ./cmd/tunnneji-tail
	```

## ライセンス
本リポジトリは、独自のアプリケーション・ロジックと基盤となるネットワークエンジンを区別するため、複数のライセンスのもとで提供されています。

* **オリジナル・アプリケーション部分 (AGPL-3.0):**
  `cmd/tunnneji-tail/` ディレクトリ配下のすべてのコード（CLIロジック、ポートフォワーディング、ChaCha20暗号化フック、ゼロトラストの全体設計など）は、**GNU Affero General Public License v3.0 (AGPL-3.0)** のもとで公開されています。（詳細は `LICENSE` ファイルを参照）

* **ネットワーク・エンジン部分 (BSD-3-Clause):**
  本プロジェクトは、基盤となるネットワークエンジンとして Tailscale のコードを利用・大幅に改変しています。`cmd/tunnneji-tail/` 以外のディレクトリに存在する基盤コード（WireGuard実装、NATトラバーサル、ユーザー空間のTCP/IPスタック等）は、Tailscale Inc. および貢献者によって開発されたものであり、元の **BSD 3-Clause License** が適用されます。（詳細は `LICENSE-Tailscale` ファイルを参照）