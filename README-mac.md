
You will need Apple's Xcode (at least version 7, preferably 8.x) and the Xcode Command Line Tools:

https://itunes.apple.com/us/app/xcode/id497799835?mt=12

And Homebrew:

http://brew.sh/

Use the brewfile to install the necessary packages:

```shell
brew bundle
```

or 

```shell
brew tap discoteq/discoteq; brew install flock autoconf autogen automake gcc@8 binutils protobuf coreutils wget
```

Get all that installed, then run:

```shell
git clone https://github.com/VerusCoin/VerusCoin.git
cd VerusCoin
./zcutil/build-mac.sh
./zcutil/fetch-params.sh
```

Happy Building
