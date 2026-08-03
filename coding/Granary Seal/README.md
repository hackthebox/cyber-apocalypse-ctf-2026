![](../../assets/banner.png)

<img src="../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align="left" />        <font size="10">Granary Seal</font>

​        9<sup>th</sup> July 2026

​        Prepared By: 131LL

​        Challenge Author(s): 131LL

​        Difficulty: <font color=green>Very Easy</font>


# Synopsis

Granary Seal is a very easy coding challenge that requires the player to validate a batch of three-hand ration orders against three independent custody rolls. The solution is a direct membership check against a hash set for each of the three roles, with no data structures beyond a set required.

## Skills Required

- Basic I/O parsing
- Using hash sets for O(1) membership testing
- Looping and counting

## Skills Learned

- Reducing an "is this hand trusted" check to set membership
- Structuring a multi-field validation check cleanly

## Description

```
The palace granaries of Crownspire depend on trust in three hands — clerk,
countersigner, and courier — but forged ration orders are slipping past the
gatehouse. Lysa Harrowmere needs to know how many orders in the latest batch
survive the old sequence clean.
```

## Technical Description

```
Granary Seal
C clerks, CS countersigners, and R couriers are named on Lysa's custody
rolls, each given as a separate list. N orders follow, each listing a
clerk, a countersigner, and a courier. An order survives the old sequence
if and only if all three hands appear on their respective custody roll.
Count and print the number of orders that survive.

Line 1: C
Next C lines: clerk name
Line: CS
Next CS lines: countersigner name
Line: R
Next R lines: courier name
Line: N
Next N lines: clerk countersigner courier

1 <= C, CS, R <= 20
1 <= N <= 5000
Names consist of lowercase letters and dots, length <= 30
An order survives only if all three hands are on their role's custody roll

Example Input:
3
aldric.vowmark
bren.irongate
seyna.saltholm
3
voss.ashglass
tal.greywater
mira.crownwall
3
garren.cinders
lysa.stonepass
elric.brinemark
7
aldric.vowmark voss.ashglass garren.cinders
bren.irongate tal.greywater lysa.stonepass
cassian.embervane voss.ashglass garren.cinders
aldric.vowmark forger.oathstone garren.cinders
seyna.saltholm mira.crownwall ghost.saltwind
bren.irongate voss.ashglass elric.brinemark
seyna.saltholm tal.greywater garren.cinders

Expected output:
4
```

## Solving the challenge

### Step 1: Recognise the three checks as set membership

Each custody roll — clerks, countersigners, couriers — is just a list of hands the gatehouse has already watched work for that one role. "Is this clerk trusted?" is exactly the question "does this name belong to the clerk set?" Loading each roll into a `set` turns an O(C) linear scan into an O(1) lookup per name.

### Step 2: Parse the three custody rolls

Read each roll's size, then that many names into its own set.

```python
C = int(input())
clerks = {input() for _ in range(C)}

CS = int(input())
countersigners = {input() for _ in range(CS)}

R = int(input())
couriers = {input() for _ in range(R)}
```

### Step 3: Parse and check each order

Each order line holds exactly three space-separated names, in clerk / countersigner / courier order. An order survives only if every one of the three hands is present in its matching set.

```python
N = int(input())
valid = 0
for _ in range(N):
    c, cs, co = input().split()
    if c in clerks and cs in countersigners and co in couriers:
        valid += 1
```

### Step 4: Print the count

```python
print(valid)
```

### Step 5: Fast I/O for larger inputs

The largest hidden test cases have up to 5000 orders and rolls of 20 names each — trivial for `input()` in Python, but per-line reads still carry overhead that adds up. Since names never contain whitespace, the entire input can be treated as one flat stream of tokens instead of a sequence of lines:

```python
data = sys.stdin.buffer.read().split()
```

An index cursor is then advanced manually as each value is consumed — one call to read a count, and one to pull that many names into a set — replacing the `input()` calls from Steps 2 and 3 with lookups into `data`. The membership logic itself (build three sets, then check each order against all three) doesn't change at all; only the parsing layer underneath it gets faster.

### Worked example

| Order | Clerk | Countersigner | Courier | Verdict |
|---|---|---|---|---|
| 1 | aldric.vowmark ✓ | voss.ashglass ✓ | garren.cinders ✓ | Survives |
| 2 | bren.irongate ✓ | tal.greywater ✓ | lysa.stonepass ✓ | Survives |
| 3 | cassian.embervane ✗ | voss.ashglass ✓ | garren.cinders ✓ | **Fails** (clerk not on the roll) |
| 4 | aldric.vowmark ✓ | forger.oathstone ✗ | garren.cinders ✓ | **Fails** (countersigner not on the roll) |
| 5 | seyna.saltholm ✓ | mira.crownwall ✓ | ghost.saltwind ✗ | **Fails** (courier not on the roll) |
| 6 | bren.irongate ✓ | voss.ashglass ✓ | elric.brinemark ✓ | Survives |
| 7 | seyna.saltholm ✓ | tal.greywater ✓ | garren.cinders ✓ | Survives |

Four orders survive the old sequence → output 4.

### Complexity

| Approach | Time | Space |
|---|---|---|
| Linear scan of custody rolls per order | O(N × (C + CS + R)) | O(C + CS + R) |
| Hash set membership | O(C + CS + R + N) | O(C + CS + R) |

Building the three sets once and checking membership per order is linear in the total input size — there is no faster approach, since every name in the input must be read at least once.
