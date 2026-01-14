# modbus-robustness-tester

Modbus Robustness Tester は、Modbus通信を含む機器に対して、
想定外の通信が行われた場合でもクラッシュやハングアップを起こさないことを確認するための耐性評価ツールです。

本ツールは、正常系および異常系のModbusコマンドを送信し、
機器が最低限の安定性を維持できているかを確認することを目的としています。

## 1.なぜ作ったか

## 2.対象とする環境

本ツールは以下の環境で動作確認を行っています。

- **OS**: Windows 10 / 11（※ macOS / Linux でも Python が動作すれば利用可能）
- **Python**: 3.10 〜 3.12
- **必要ライブラリ**
  - `なし`（標準ライブラリのみ使用）  

---

## 3.クイックスタート

### 3.1. EXE版を使う

#### 3.1.1. ダウンロード
Windows 向けの実行ファイル（exe）は  
GitHub Releases ページからダウンロードできます。

➡ **[Releases ページはこちら](https://github.com/prevalmam/modbus-robustness-tester/releases)**

最新バージョンの Assets から  
`modbus-robustness-tester.exe` をダウンロードしてください。

#### 3.1.2. SHA-256（検証用）

配布している実行ファイルの SHA-256 ハッシュ値は  
Releases の Assets に含まれる `SHA256SUMS.txt` に記載しています。

ダウンロード後、以下のコマンドで検証できます。

```powershell
certutil -hashfile modbus-robustness-tester.exe SHA256
```
出力されたハッシュ値が SHA256SUMS.txt に記載されている値と一致すれば、
ファイルが改ざんされていないことを確認できます。

### 3.2. ソースコードから使う

#### 3.2.1. git clone + pip install
次に示すコマンドを実行して，ソースコードをクローンし，pip でインストールします。

```powershell
git clone https://github.com/prevalmam/modbus-robustness-tester.git
cd modbus_robustness_tester
pip install .
```

#### 3.2.2. 使い方

1. コマンドラインから以下を実行します。

```powershell
mb-robust
```
2. hoge


