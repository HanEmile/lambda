#from pwn import *
import itertools
import re
import random
import functools

alpha = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
            'y', 'z']

print(30*"=*")

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

#p = remote("34.141.16.87", 60000)
#p.interactive()

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
    print()
    print(f"[] {a=}")
    print(f"[] {b=}")

    a = list(a)
    b = list(b)

    a = normalize(a)
    b = normalize(b)

    a = ''.join(a)
    b = ''.join(b)

    print(f"[] {a=}")
    print(f"[] {b=}")

    return a == b

def beta_reduce(expression):
    # used to track "free" variable names
    alphabet_free = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                'y', 'z']
    alphabet_used = []

    print(f"[i] input: {expression}")

    ####################  parse the func
    func = get_expr(expression, True)[0]
    expression = expression.replace(func, "", 1).strip() # delete func from expression
    print(f"[i] \t| {func=}")

    ####################  parse the parameters
    params = re.search("λ([a-z ]+)\.", func).group(1).split(" ")
    for val in params:
        if val in alphabet_free:
            alphabet_free.remove(val)
        if val not in alphabet_used and val in alpha:
            alphabet_used.append(val)
    alphabet_free = list(set(alphabet_free))
    print(f"[i] \t| {params=}")

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
    print(f"[i] \t| {body=}")

    ####################  parse the args
    args = get_expr(expression, False)
    if '' in args: # otherwise we get in the loop below
        args.remove('')
    if ' ' in args: # otherwise we get in the loop below
        args.remove(' ')
    print(f"[i] \t| {args=}")

    #print(f"[i] \t| {alphabet_free=}")
    #print(f"[i] \t| {alphabet_used=}")

    count_remove = 0 # amount of params/args to remove

    for i in range(0, len(args)):

        # all params have been handled, break
        if count_remove == len(params):
            break

        print(f"[ ] {i=} {args[i]=} {params[i]=}")

        # for each element in the body, try to replace the parameter with the
        # provided argument
        for j in range(0, len(body)):
            print(f"    {i=} {j=} {body[j]} {params[i]=} {args[i]=}")
            new_arg = args[i]

            available_alph = [char for char in alphabet_free if char not in new_arg]

            if params[i] in body[j]:

                partial_alphabet = []
                for letter in alphabet_used:
                    if letter in new_arg:
                        #print(f"{alphabet_free=}")
                        #print(f"{alphabet_used=}")
                        char = available_alph[0]

                        print(f"--> {new_arg} {letter} {char}")
                        new_arg = new_arg.replace(letter, char)
                        print(f"--> {new_arg} {letter} {char}")

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
    while expression[1] == "λ" and len(get_expr(expression))>1:
        expression = beta_reduce(expression).strip()
        print(f"[d] {expression=}")
    return expression

################################################################################



primitives = {}
primitives["TRUE"] = "(λc d. c)"
primitives["CONST_TRUE"] = f'(λa. {primitives["TRUE"]})'
primitives["FALSE"] = "(λe f. f)"
primitives["CONST_FALSE"] = f'(λb. {primitives["FALSE"]})'
primitives["AND"] = "(λa b. a b a)"
primitives["OR"] = f'(λa b. a a b)'
primitives["IDENDTITY1"] = f'(λa. a)'

@functools.lru_cache()
def gen_funcs(params=2):
    ret = []
    permutations = [x for x in itertools.product(''.join(alpha[:params]),
                                                 repeat=params)]
    params = " ".join([alpha[i] for i in range(0, params)])
    for body in permutations:
        body = " ".join(body)
        ret.append(f'(λ{params}. {body})')

    return ret

funcs2 = gen_funcs(params=2)
funcs3 = gen_funcs(params=3)
funcs4 = gen_funcs(params=4)

primi = primitives

#expr = f'{primi["AND"]} {primi["TRUE"]} {primi["OR"]}'
#r2 = recurse(expr)
#print(f"{r2=}")

print(60*"-")

#possible_vals = [expr_true, expr_false, expr_and, expr_or,
possible_vals = [[a for a in primi.values()], funcs2, funcs3, funcs4]

s = "(λa b. a (a b))"
t = "(λa b. a (a a))"
print(f"[ ] {s=}")
print(f"[ ] {t=}")

goal_s = "(λa b. a)"
goal_t = "(λa b. b)"
print(f"[ ] {goal_s=}")
print(f"[ ] {goal_t=}")

while True:
    rand1 = random.choice(random.choice(possible_vals))
    rand2 = random.choice(random.choice(possible_vals))
    print(f"[ ] {s=}")
    print(f"[ ] {rand1=}")
    print(f"[ ] {rand2=}")

    term_s = " ".join([s, rand1, rand2])
    term_t = " ".join([t, rand1, rand2])
    print(f"[ ] {term_s=}")
    print(f"[ ] {term_t=}")

    r_s = recurse(term_s)
    r_t = recurse(term_t)
    print(f"[ ] {r_s=}")
    print(f"[ ] {r_t=}")

    print(f"[ ] {match(r_s, goal_s)=}")
    print(f"[ ] {match(r_t, goal_t)=}")

    if match(r_s, goal_s) and match(r_t, goal_t):
        print(40*"=")
        print(f"[ ] {s=} {t=}")
        print(f"[ ] {rand1=}")
        print(f"[ ] {rand2=}")
        print(f"[ ] {goal_s=}")
        print(f"[ ] {r_s=}")
        print(f"[ ] {rand1=}")
        print(f"[ ] {rand2=}")
        print(40*"=")
        break
