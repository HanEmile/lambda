from pwn import *
import itertools
import re
import random
import functools
import time

import logging

random.seed(time.time())

alpha = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
            'y', 'z']

#print(30*"=*")

# ------------------ EXAMPLE ------------------
# s = λb ε. ε b     -> s = λx y. x
# t = λb ε. b ε     -> s = λx y. y
# Please provide inputs [v1, v2, v3, ..., vn] such that:
# 	((s) (v1) (v2) (v3) ... (vn)) beta-reduces to (λx y. x)
# 	((t) (v1) (v2) (v3) ... (vn)) beta-reduces to (λx y. y)
# 
# How many terms do you want to input? 2
# Please input term 1: (λa . (λx y . y))
# Please input term 2: (λa . (λx y . x))
# Correct!

#(λe. e (λa . (λx y . y))  (λa . (λx y . x)))
#(λa . (λx y . y)))  (λa . (λx y . x))

# [m] (λa b. a b a) (λa b. a) (λa b. b)
# [m] (λa b. (λc d. c) b a) (λa b. b)
# [m] (λa b. (λc d. c) b (λe f. e)) (λa b. b)
# [m] (λa b. (λc d. c) (λg h. g) (λe f. e)) 


def get_expr(value, get_func=False):
    brace_count = 0
    ret = []

    partial_ret = ""
    
    for char in value:
        if char == "(":
            brace_count += 1
        if char == ")":
            brace_count -= 1

        partial_ret += char

        if brace_count == 0:
            ret.append(partial_ret)
            partial_ret = ""

            # only get func, stop at first occurence of brace_count = 0
            if get_func == True:
                break
            else:
                # only stop at end of string
                # we're contining until we're done with the string
                pass

    if '' in ret:
        ret.remove('')
    if ' ' in ret:
        ret.remove(' ')

    return ret

def normalize(expr):
    alphabet_free = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                'y', 'z']
    alph = alphabet_free.copy()
    mappings = {}

    for i, char in enumerate(expr):
        if char in alph:
            if char not in mappings:
                newchar = alphabet_free[0]
                alphabet_free.remove(newchar)
                mappings[char] = newchar
            else:
                newchar = mappings[char]

            expr[i] = newchar

    return expr

def match(a, b):
    #print()
    #print(f"[] {a=}")
    #print(f"[] {b=}")

    a = list(a)
    b = list(b)

    a = normalize(a)
    b = normalize(b)

    a = ''.join(a)
    b = ''.join(b)

    #print(f"[] {a=}")
    #print(f"[] {b=}")

    return a == b

def beta_reduce(expression):
    # used to track "free" variable names
    alphabet_free = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                'y', 'z']
    alphabet_used = []

    #print(f"[i] input: {expression}")

    ####################  parse the func
    func = get_expr(expression, True)[0]
    expression = expression.replace(func, "", 1).strip() # delete func from expression
    #print(f"[i] \t| {func=}")

    ####################  parse the parameters
    params = re.search("λ([a-z ]+)\.", func).group(1).split(" ")
    for val in params:
        if val in alphabet_free:
            alphabet_free.remove(val)
        if val not in alphabet_used and val in alpha:
            alphabet_used.append(val)
    alphabet_free = list(set(alphabet_free))
    #print(f"[i] \t| {params=}")

    ####################  parse the body
    body = re.search("λ[a-z ]+\.([λ.()a-z ]+)\)", func).group(1)[1:]
    body = get_expr(body)

    for val in body:
        if val in alphabet_free:
            alphabet_free.remove(val)
        if val not in alphabet_used and val in alpha:
            alphabet_used.append(val)
    alphabet_free = list(set(alphabet_free))
    if ' ' in body: # otherwise we get in the loop below
        body.remove(' ')
    #print(f"[i] \t| {body=}")

    ####################  parse the args
    args = get_expr(expression, False)
    if '' in args: # otherwise we get in the loop below
        args.remove('')
    if ' ' in args: # otherwise we get in the loop below
        args.remove(' ')
    #print(f"[i] \t| {args=}")

    #print(f"[i] \t| {alphabet_free=}")
    #print(f"[i] \t| {alphabet_used=}")

    count_remove = 0 # amount of params/args to remove

    for i in range(0, len(args)):

        # all params have been handled, break
        if count_remove == len(params):
            break

        #print(f"[ ] {i=} {args[i]=} {params[i]=}")

        # for each element in the body, try to replace the parameter with the
        # provided argument
        for j in range(0, len(body)):
            #print(f"    {i=} {j=} {body[j]} {params[i]=} {args[i]=}")
            new_arg = args[i]

            available_alph = [char for char in alphabet_free if char not in new_arg]

            if params[i] in body[j]:

                partial_alphabet = []
                for letter in alphabet_used:
                    if letter in new_arg:
                        #print(f"{alphabet_free=}")
                        #print(f"{alphabet_used=}")
                        char = available_alph[0]

                        #print(f"--> {new_arg} {letter} {char}")
                        new_arg = new_arg.replace(letter, char)
                        #print(f"--> {new_arg} {letter} {char}")

                        alphabet_free.remove(char)
                        available_alph.remove(char)
                        if char not in alphabet_used:
                            partial_alphabet.append(char)

                alphabet_used.extend(partial_alphabet)


            body[j] = body[j].replace(params[i], new_arg)

            #print(f"    new body char {body[j]}")
            #print(f"    new body = {' '.join(body)}")

        count_remove += 1

    #for char in params[:count_remove]:
    #    alphabet_used.remove(char)
    #    alphabet_free.append(char)

    params = params[count_remove:]
    args = args[count_remove:]

    #print(f"{len(alphabet_free)=}")
    #print(f"{len(alphabet_used)=}")
    #print(f"{alphabet_used=}")

    if len(params) == 0:
        # return espression only
        new_params = " ".join(params)
        new_body = " ".join(body)
        new_args = " ".join(args)

        new_expression = f"{new_body} {new_args}"
        return new_expression
    else:

        # return partially applied function
        new_params = " ".join(params)
        new_body = " ".join(body)
        new_args = " ".join(args)

        new_expression = f"(λ{new_params}. {new_body}) {new_args}"
        return new_expression

# get an expression and beta reduce it as long as it is a function or starts
# with a function
def recurse(expression):
    expression = expression.strip()
    depth = 0

    try:
        while expression[1] == "λ" and len(get_expr(expression))>1:
            expression = beta_reduce(expression).strip().replace("  ", "")
            #print(f"[1d {depth}] {expression=}")
            if expression[:2] == '((':
                #print(f"[2d {depth}] {expression[:2]=}")
                # remove extra bracket (left associativity)
                para = get_expr(expression, get_func=True)[0]
                #print(f"{para=}")
                expression = expression[1:len(para)-1] + expression[len(para):]
                #print(f"[3d {depth}] {expression=}")
            depth += 1

            if depth >= 10:
                break
    except:
    #except Exception as e:
    #    logging.exception(e)
    #    print(expression)
        pass

    return expression.replace("  ", "")

################################################################################

primitives = {}
primitives["TRUE"] = "(λc d. c)"
primitives["CONST_TRUE"] = f'(λa. {primitives["TRUE"]})'
primitives["FALSE"] = "(λe f. f)"
primitives["CONST_FALSE"] = f'(λb. {primitives["FALSE"]})'
primitives["AND"] = "(λa b. a b a)"
primitives["OR"] = f'(λa b. a a b)'
primitives["IDENDTITY1"] = f'(λa. a)'
primitives["NOT"] = f'(λp. p {primitives["FALSE"]} {primitives["TRUE"]})'

@functools.lru_cache()
def gen_funcs(param_count=2, body_count=3):
    ret = []

    params = " ".join([alpha[i] for i in range(0, param_count)])

    product = [x for x in itertools.product(''.join(alpha[:param_count]),
                                                 repeat=body_count)]
    for body in product:
        body = " ".join(body)
        ret.append(f'(λ{params}. {body})')

    return ret

funcs1 = gen_funcs(param_count=2, body_count=1)
funcs2 = gen_funcs(param_count=2, body_count=3)
funcs3 = gen_funcs(param_count=3, body_count=4)
funcs4 = gen_funcs(param_count=4, body_count=4)

manual = [
        f'(λb a c c. {primitives["TRUE"]})',
            #'(λa b f. f a b)',
            #'(λa f. f a)',
            #'(λa. a)',
            #'(λa b. a)',
            #'(λa. a)',
            #'(λa b. a)',
            #'(λa. a)',
            #'(λg h. (λc d. c))',
            #'(λg h. (λe f. f))'
        ]

#'(λv0 v1 f. f v0 v1)'
#'(λv0 f. f v0)'
#'(holder)'
#'(λv0 v1. v0)'
#'(holder)'
#'(λv0 v1. v0)'
#'(holder)'
#'(λi0 i1. (true))'
#'(λi0 i1. (false))']

#(lambda a b. a (a a)) (λv0 v1 f. f v0 v1) (λv0 f. f v0) (holder) (λv0 v1. v0) (holder) (λv0 v1. v0) (holder) (λi0 i1. (λc d. c)) (λi0 i1. (λe f. f))

#(lambda a b. a (a b)) (λv0 v1 f. f v0 v1) (λv0 f. f v0) (holder) (λv0 v1. v0) (holder) (λv0 v1. v0) (holder) (λi0 i1. (λc d. c)) (λi0 i1. (λe f. f))

#for s = λa b. a (a a), you can give it a = (λz x y. x); b = (λz. z)

primi = primitives

#expr = f'{primi["AND"]} {primi["TRUE"]} {primi["OR"]}'
#r2 = recurse(expr)
#print(f"{r2=}")

#print(60*"-")

possible_vals = [[a for a in primi.values()], funcs1, funcs2, funcs3, manual]
#possible_vals = [[a for a in primi.values()], manual]
#possible_vals = [[a for a in primi.values()], funcs2, funcs3]
#possible_vals = [[a for a in primi.values()], funcs3, manual]
#possible_vals = [[a for a in primi.values()], funcs2]


############################################################
# Brute Forcer
############################################################



total_len = len([b for a in possible_vals for b in a])

def brute_force(level, s, t, goal_s, goal_t):
    start = time.time()
    time.sleep(0.01)

    CHUNK_SIZE = 100
    running = True

    counter = 0
    while running:
        now = time.time()
        elapsed = now - start
        fcps = int(counter / elapsed)
        print(f"\r| {level:4} | {fcps:5} | {counter:10} / {total_len:4} | {s} | {t}", end="")

        for i in range(0, CHUNK_SIZE):

            rands = []

            for i in range(0, random.choice(range(10))):
                rands.append(random.choice(random.choice(possible_vals)))

            term_s = " ".join([s, *rands])
            term_t = " ".join([t, *rands])

            r_s = recurse(term_s)
            r_t = recurse(term_t)

            if match(r_s, goal_s) and match(r_t, goal_t):
            #if match(r_s, goal_s):
                print(40*"=")
                print(f"[ ] {s=} {t=}")
                print(f"[ ] {rands=}")
                print(f"[ ] {goal_s=}")
                print(f"[ ] {r_s=}")
                print(f"[ ] {r_t=}")
                print(40*"=")
                running = False
                break

        counter += CHUNK_SIZE

    return rands

def brute_force_single(level, s, goal_s):
    start = time.time()
    time.sleep(1)

    CHUNK_SIZE = 100
    running = True

    counter = 0
    while running:
        now = time.time()
        elapsed = now - start
        fcps = counter / elapsed
        print(f"\r| {level:4} | {fcps:5.2} | {counter:10} / {total_len:4} | {s} ", end="")

        for i in range(0, CHUNK_SIZE):

            rands = []

            for j in range(0, random.choice([1, 2, 3, 4])):
                rands.append(random.choice(random.choice(possible_vals)))

            term_s = " ".join([s, *rands])
            r_s = recurse(term_s)
            if match(r_s, goal_s):
                print(f"\r| {level:4} | {fcps:5.2} | {counter+i:10} / {total_len:4} | {s} ", end="")
                print(40*"=")
                print(f"[ ] {s=}")
                print(f"[ ] {rands=}")
                print(f"[ ] {goal_s=}")
                print(f"[ ] {r_s=}")
                print(40*"=")
                running = False
                break

        counter += CHUNK_SIZE

    return rands

############################################################

# r1=['(λa. (λc d. c))', '(λa b c. a c c a)']

"""
# s solutions
[ ] rands=['(λa. (λc d. c))', '(λa b c d. a c d b)']
[ ] rands=['(λe f. f)', '(λa b c. c c a c)', '(λc d. c)']
[ ] rands=['(λa b. b b b)', '(λa b. a a a)', '(λc d. c)']
[ ] rands=['(λa b. b b a)', '(λa b c d. d a d d)', '(λc d. c)']

'(λa b c d. a c d b)'
'(λa b c d. d a d d)'
'(λa b c. c c a c)'
'(λa b. a a a)'
'(λa b. b b a)'
'(λa b. b b b)'
'(λa. (λc d. c))'
'(λc d. c)'
'(λe f. f)'
"""

"""
[ ] rands=['(λb. (λe f. f))', '(λa b c d. c a a b)']
[ ] rands=['(λa b. b a b)', '(λa b. a a b)', '(λe f. f)']
[ ] rands=['(λa b. b b b)', '(λa b. b a a)', '(λe f. f)']
[ ] rands=['(λe f. f)', '(λa b c. c b b a)', '(λe f. f)']

'(λa b c d. c a a b)'
'(λa b c. c b b a)'
'(λa b. a a b)'
'(λa b. b a a)'
'(λa b. b a b)'
'(λa b. b b b)'
'(λb. (λe f. f))'
'(λe f. f)'
"""

### ########################################
### 
### #(lambda a b. a (a a)) (lambda z x y. x) (lambda x. x)
### #(lambda a b. a (a b)) (lambda z x y. x) (lambda x. x)
### #['(λv0 v1 f. f v0 v1)', '(λv0 f. f v0)', '(holder)', '(λv0 v1. v0)', '(holder)', '(λv0 v1. v0)', '(holder)', '(λi0 i1. (true))', '(λi0 i1. (false))']
### 
### func = "(λa b. a (a b))"
### args = ' '.join(['(λa b f. f a b)', '(λa f. f a)', '(λa. a)', '(λa b. a)',
###                  '(λa. a)', '(λa b. a)', '(λa. a)', '(λg h. (λc d. c))',
###                  '(λg h. (λe f. f))'])#, '(λx. x)'])
### 
### exp = f"{func} {args}"
### print(f"{exp=}")
### 
### r1 = recurse(exp)
### print(f"{r1=}")
### 
### ########################################

s='(λa b. a λc. b (a c))'
s='(λa b c. a b (a c))'
t='(λa b c. a b (a c))'
#t='(λa b. a λc. b (a a c))'
goal_s='(λx y. x)'
goal_t='(λx y. y)'
r1 = brute_force(0, s, t, goal_s, goal_t)
print(f"{r1=}")

exit()

#for i in range(0, 50):
#    s = "(λa b. a (a b))"
#    t = "(λa b. a (a a))"
#    goal_s='(λx y. x)'
#    goal_t='(λx y. y)'
#    r1 = brute_force(0, s, t, goal_s, goal_t)
#    #r1 = brute_force_single(0, s, goal_s)
#
#    for option in possible_vals:
#        if r1[0] in option:
#            option = option.remove(r1[0])
#    print(f"{r1=}")
#    print()


# λ > (lambda a b. a (a a)) (lambda z x y. x) (lambda x. x)
# ω > wrap abstraction and application with brackets:
# 　　　(lambda a b. a (a a)) (lambda z x y. x) (lambda x. x) -> ((lambda a b. a (a a)) (lambda z x y. x) (lambda x. x))
# α > (((λa.(λb.(a(a a))))(λz.(λx.(λy.x))))(λx0.x0))
# β > ((λb.((λz.(λx.(λy.x)))((λz.(λx.(λy.x)))(λz.(λx.(λy.x))))))(λx0.x0))
# α > ((λb.((λz.(λx.(λy.x)))((λx0.(λx1.(λx2.x1)))(λx3.(λx4.(λx5.x4))))))(λx6.x6))
# β > ((λz.(λx.(λy.x)))((λx0.(λx1.(λx2.x1)))(λx3.(λx4.(λx5.x4)))))
# β > (λx.(λy.x))


############################################################
# Server Interaction
############################################################

p = remote("34.141.16.87", 60000)
p.readuntil(bytes("s = ", "utf-8"))

level = 0

while True:
    p.readuntil(b"s = ")
    s = "("+ p.readline().decode().strip() + ")"
    print(f"{s=}")

    p.readuntil(b"t = ")
    t = "(" + p.readline().decode().strip() + ")"
    print(f"{t=}")

    p.readuntil(b"beta-reduces to ")
    goal_s = p.readline().decode().strip()
    print(f"{goal_s=}")
    p.readuntil(b"beta-reduces to ")
    goal_t = p.readline().decode().strip()
    print(f"{goal_t=}")

    # solve
    res = brute_force(level, s, t, goal_s, goal_t)
    print(res)

    p.readline()
    p.sendlineafter("want to input? ", str(len(res)).encode('utf-8'))

    for i in range(1, len(res)+1):
        p.sendlineafter(f"term {i}: ", str(res[i-1]).encode('utf-8'))

    #p.interactive()
    level += 1

# LOOK INTO:
#61322 /         96 | (λa b. a (b a)) | (λa b. a (b b))


#s = "(λa b. a a)"
#t = "(λa. a a)"
#goal_s = primitives["TRUE"]
#goal_t = primitives["FALSE"]
#print(brute_force(s, t, goal_s, goal_t))
