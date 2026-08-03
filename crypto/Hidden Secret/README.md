![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font 
size='6'>Name</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: WizardAlfredo

Challenge Author(s): WizardAlfredo

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- TBD

## Description

- I received this lovely letter but the sender put a seal on it. She said that can be opened only 
at our place, Rhome.

## Skills Required

- Basic Python source code analysis.
- Basic research skills.
- Basic mathematical skills.
- Basic understanding of how AES modes works.
- Knowledge about ECC.

## Skills Learned

- Combining online resources to ?
- Combining online resources to exploit a chain of vulnerabilities.
- Better understanding of cryptography used in ?.
- Better understanding of ? and corresponding attacks.
- Better understanding of the ? cryptosystem and its weaknesses.

# Enumeration

## Analyzing the source code

If we look at the `source.py` script we can see that our goal is to

The basic workflow of the script is as follows:

1.
2.

Steps 1, 2, and 4 are

```python

```

A little summary of all the interesting things we have found out so far:

1.
2.

# Solution

## Finding the vulnerability

TBD

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == "__main__":
    r = remote("0.0.0.0", 1337)
    pwn()
```

### TBD

TBD

```python

```

### Getting the flag

A final summary of all that was said above:

1.
2.

This recap can be represented by code with the `pwn()` function:

```python
def pwn():

```
