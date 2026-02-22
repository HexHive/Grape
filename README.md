
# Squeezing Juicy Variant Bugs Out of Modern Browsers

This repo include the queries we used for scanning the variant bugs 
in the Chromium and VSCode. All queries can be re-implemented 
in any analyzer that support AST and variable name matching.

For more details, check out our [paper](https://kdsjzh.github.io/assets/pdf/26WOOT.pdf).
Please consider cite our work if you find it useful.
```
@inproceedings{zheng2026grape,
  title={Squeezing Juicy Variant Bugs Out of Modern Browsers},
  author={Zheng, Han and Toffalini, Flavio and Liu, Qiang and Payer, Mathias},
  booktitle={20th USENIX WOOT Conference on Offensive Technologies (WOOT 26)},
  year={2026}
}
```

## Preparing Environment

The Grape take program source as input and does not necessciate the compilation. 
Thus, please download the VSCode and Chromium source code following the official 
instructions, then checkout to the versions specified in the paper.

**Note: When switching chromium version, please do both `git checkout version_tag` AND 
`gclient sync -D`, otherwise only main chromium source code are changed and third-party 
components remain not changed.**

Grape itself requires python 3.10, semgrep 1.90.0 and grep, and in most OS, 
python and grep are available and the user only need to install the semgrep via 
`pip3 install semgrep==1.90.0`.


## Preprocessing

Semgrep, at the time we develop Grape, do not support some advance C++ features like 
```cpp
for (auto& [a, b] : c) {
    ...
  }

```
or 
```cpp
LIBYUV_API
int FuncName(...)
```
So we recommend preprocessing the sourcecode using following:

* Bug variant 5: Run `sed -i 's/LIBYUV_API//g' third_party/libyuv/source/*.cc`

* Bug variant 3: Run
```sh
# sed -E -i 's/for \(auto& \[([a-z_]+), [a-z_]+\] : ([a-z_]+)\)/for (auto \1 : \2)/' third_party/blink/renderer/core/css/resolver/style_cascade.cc
# sed -E -i 's/for \(const auto& \[([a-z_]+), [a-z_]+\] : ([a-z_]+)\)/for (const auto \1 : \2)/' third_party/blink/renderer/core/css/resolver/style_cascade.cc

find third_party/blink -type f -name "*.cc" \
  -exec sed -E -i 's/for \(auto& \[([a-z_]+), [a-z_]+\] : /for (auto \1 : /' {} \;

find third_party/blink -type f -name "*.cc" \
  -exec sed -E -i 's/for \(const auto& \[([a-z_]+), [a-z_]+\] : /for (const auto \1 : /' {} \;
```

Moreover, we hardcode some FPs for the UI and JS patterns, thus the future researchers can 
exclude them directly when hunting for new vulnerbilities. 
**Thus, when reproducing the paper claims, please remove ALL fp list in config/false_positive/**, 
otherwise the FP rate will be notably lower than reported results in the paper.


## Usage

```bash
# usage, if evaluating pattern 6, use the vscode 1.99.0
# if evaluating pattern 1-5, use chrome 126.0.6465.2

python3 src/main.py -t $TMP_DIR -r /path/to/chrome $BUG_VARIANT

# e.g.
python3 src/main.py -t temp/  -r /home/usr/workspace/download/chrome/src ui

```

Some explainations of the output:
* "In total, we found 68 violation functions." -> Some patten automatically find 
`violation` functions, this reflect to the "violations" column in Table 5. 
* "In total, we found 27 potential vulnerbilities among 68 violation functions." ->
The final findings, the "With Filtering" column in Table 5. These findings include 
FPs.
* All the TP results (those reported by us, in Table 4) are included in the 
Grape findings. The user may manually compare the chrome issuetracker report and 
Grape findings.


## Reproduce Data in the paper

We start use this tool to find bugs since May 2024, so all our FP rates 
are computed based on 126.0.6468.2, in which non of the reported bugs are fixed.



## Reported and Fixed Findings

The new vulnerbilites/bugs found and reported by our prototype.

| ID        | Variant                                                                          | Component                         | Type          | Severity | Status     | Bounty |
|-----------|----------------------------------------------------------------------------------|-----------------------------------|---------------|----------|------------|--------|
| 1 | JS UAF | Internal > Plugin > PDF           | Vulnerability | Medium   | CVE        |   1000 |
| 2 | JS UAF | Internal > Plugin > PDF           | Vulnerability | Medium   | CVE        |   1000 |
| 3 | UI UAF | Internal > Headless               | Vulnerability | Low      | Fixed      |      0 |
| 4 | UI UAF | UI > Shell                        | Bug           | Medium   | Fixed      |      0 |
| 5 | UI UAF | UI > Browser > Autofill           | Vulnerability | High     | CVE        |   1000 |
| 6 | UI UAF | UI > Aura                         | Bug           | Medium   | Fixed      |      0 |
| 7 | UI UAF | Unclassified                      | Vulnerability | Medium   | Fixed      |    500 |
| 8 | UI UAF | Internals > Views > Desktop       | Vulnerability | Low      | Fixed      |      0 |
| 9 | UI UAF | Unclassified                      | Vulnerability | High     | Duplicated |      0 |
| 10 | UAR    | Blink > CSS                       | Vulnerability | High     | Fixed      |  11000 |
| 11 | Int Overflow (add) | Internals > Skia      | Vulnerability | High     | CVE      |   3000 |
| 12 | Int Overflow (Multiply) | Blink > WebRTC                    | Vulnerability | High     | Fixed      |      0 |
| 13 | Int Overflow (Multiply) | Blink > WebRTC                    | Vulnerability | Medium   | Fixed      |      0 |
| 14 | Improper Access Control | VSCode                    | Vulnerability | High   | -      |      0 |
| 15 | Improper Access Control | AzureDataStudio           | Vulnerability | Low    | Fixed  |      0 |
| 16 | Improper Access Control | AzureDataStudio           | Vulnerability | High   | CVE    |      0 |
