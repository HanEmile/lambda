# Nix HackTM CTF - 'know your lambda calculus'

challenge dev setup

Get a shell:

```bash
; nix develop

# enable flakes if you haven't:
; nix --experimental-features 'nix-command flakes' develop
```

Exec solve script:

```bash
[HackTM CTF lambda]; python3 solve.py 
```

## Known problems

function generation can be made better, I'm only doing vaiable param and body
count, but no function in body or so.

## Example

```
------------------ EXAMPLE ------------------
s = λb ε. ε b
t = λb ε. b ε
Please provide inputs [v1, v2, v3, ..., vn] such that:
	((s) (v1) (v2) (v3) ... (vn)) beta-reduces to (λx y. x)
	((t) (v1) (v2) (v3) ... (vn)) beta-reduces to (λx y. y)

How many terms do you want to input? 2
Please input term 1: (λa . (λx y . y))
Please input term 2: (λa . (λx y . x))
Correct!
---------------------------------------------

------------------ challenge 1/1000 ------------------
s = λa. a a
t = λa b. a b
Please provide inputs [v1, v2, v3, ..., vn] such that:
	((s) (v1) (v2) (v3) ... (vn)) beta-reduces to (λx y. x)
	((t) (v1) (v2) (v3) ... (vn)) beta-reduces to (λx y. y)

How many terms do you want to input?
```

---

## Cache

Caching implemented, view the current cache here: [cache.md](./cache.md)

format:

```
((s, t), (goal_s, goal_t)) ['(v1)', '(v2)', '(v3)', ...]
```

## Cannot Solve

Caching implemented, view the current cache here: [cache.md](./cache.md)

Input expressions that cannot be solved are logged here: [cannot_solve.md](./cannot_solve.md)

format:

```
(s) | (t)
```


## Challenge Description

Let's have some fun with Lambda Calculus!

`nc 34.141.16.87 60000`

Added example:

Question:
```
s = λa b. a (a b)
t = λa b. a (a a)
```

Solution:
```
'(λv0 v1 f. f v0 v1)', '(λv0 f. f v0)', '(holder)', '(λv0 v1. v0)', '(holder)', '(λv0 v1. v0)', '(holder)', '(λi0 i1. (λx y. x))', '(λi0 i1. (λx y. y))'
```

How the interpreter reduces terms:

```
(λa b. a (λc. a a (b b c)) a) (λp0 p1. p1 p0 p0) (λp2 p3 p4 p5 p6. p3 p1) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λb. (λp0 p1. p1 p0 p0) (λc. (λp0 p1. p1 p0 p0) (λp0 p1. p1 p0 p0) (b b c)) λp0 p1. p1 p0 p0) (λp2 p3 p4 p5 p6. p3 p1) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp0 p2. p2 p0 p0) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λp0 p2. p2 p0 p0) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp2. p2 (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λp0 p2. p2 p0 p0) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp0 p2. p2 p0 p0) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp2. p2 (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp2. p2 (λp0 p2. p2 p0 p0) λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp3 p4 p5 p6. p3 p1) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp4 p5 p6. (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) p1) (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp5 p6. (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) p1) (λp0 p2. p2 p0 p0) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp6. (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) p1) (λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λc. (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) c)) p1 (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) p1) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp2. p2 (λp0 p2. p2 p0 p0) λp0 p2. p2 p0 p0) ((λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) p1) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp2 p3 p4 p5 p6. p3 p1) (λp2 p3 p4 p5 p6. p3 p1) p1 (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp3 p4 p5 p6. p3 p1) p1 (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp4 p5 p6. p1 p1) (λp0 p2. p2 p0 p0) (λp0 p2. p2 p0 p0) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp5 p6. p1 p1) (λp0 p2. p2 p0 p0) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
(λp6. p1 p1) (λq q q q q q q q x y. y) (λq q q q q q q x y. x) e f g h i
p1 p1 (λq q q q q q q x y. x) e f g h i
```
