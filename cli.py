__is_running__ = False
__commands__ = dict()


def set_visible(func):
    """Adds the function name to the commands, i.e. makes her visible"""
    __commands__[func.__name__] = func
    return func


@set_visible
def help():
    """Write commands details"""
    print('List commands:')
    for k, v in __commands__.items():
        print('\t{}\t--{}'.format(k, v.__doc__))

@set_visible
def exit():
    """Exit the program"""
    global __is_running__
    __is_running__ = False


def run():
    global __is_running__
    __is_running__ = True

    while __is_running__:
        line = input()
        cmd, *args = line.split(' ')
        if cmd in __commands__:
            func = __commands__.get(cmd)
            res = func(*args)
            if res: 
                print(res)
        else:
            __commands__.help()
