Create a container to use emulator.

```bash
git clone git@github.com:MustBastani/panda.git
docker image build -t loris-emulator .
docker container run -it -v $(pwd):/firmwire --name loris-emulator loris-emulator
```

You probably do not need this. To compile panda when developing:
```bash
cd /firmwire_deps/
cp -r /firmwire/panda/ . && pushd panda/build && CFLAGS=-Wno-error ../build.sh --python arm-softmmu,mipsel-softmmu && popd
```

