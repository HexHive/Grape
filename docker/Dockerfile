FROM ubuntu:22.04 

RUN apt update && apt install python3 git python3-pip -y 

RUN python3 -m pip install semgrep==1.90.0

# maybe install dependencies by pip install -r requirement.txt

# prepare chromium source
RUN mkdir -p evaluation/126.0.6423.0 && pushd evaluation/126.0.6423.0 && \
    git clone --branch 126.0.6423.0 --depth=1 https://chromium.googlesource.com/chromium/src.git && \
    popd 


# python3 main.py -t $PWD/temp -r evaluation/126.0.6423.0/src ui