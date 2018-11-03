# K-Hunt Crypto Challenge for CCS'18

------

# Introduction

This challenge is designd for our CCS paper: **"K-Hunt: Pinpointing Insecure Cryptographic keys from Execution Traces"**. It involves a deterministically generated key (DGK) case used in `Imagine`, an image and animation viewer. In this case, the software uses a DSA signing mechanism to generate its license code. Due to the fixed `k` (a random number required in a DSA signing) used, it is able to recover the private key with a valid signature.

# Challenge

To win this challenge, you are expected to provide **your own name and a corresponding license code** other than the existing license code

```
Name/Company:  romangol
License code:  2b2edd1ca726af1c95e392df7bbf586926c01af9
```

provided within the `imagineViewer.7z` in this directory. If you've got the answer, please email it to `loccs@sjtu.edu.cn`, we will reply ASAP. If you win this challenge, there will be a little reward waiting for you. Please go to the ant-financial desk at the 1st floor of Beanfield center to acquire your gift!

Note that we have modified the public key in our provided `Imagine` program so that all license codes in our challenge are unavailable in the original version.

Enjoy the challenge!