処理系のインストール。1.28.0での動作を確認しているが恐らくそれ以上のstableコンパイラなら問題ないはず。

```sh
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/env
```

実行


```rust
cargo run --release
```


バイナリは `target/release/isubata` にある。
