class cli:
    def __init__(self):
        super().__init__()
        self.__is_running__ = False
        self.__commands__ = dict()
        self.add(self.help)
        self.add(self.exit)

    def add(self, func):
        """Adds the function name to the commands, i.e. makes her visible"""
        self.__commands__[func.__name__] = func
        return func

    def help(self):
        """Write commands details"""
        print('List commands:')
        for k, v in self.__commands__.items():
            print('\t{}{}--{}'.format(k, (30-len(k))*' ', v.__doc__))

    def exit(self):
        """Exit the program"""
        self.__is_running__ = False

    def run(self):
        self.__is_running__ = True

        while self.__is_running__:
            line = input().split(' ')
            cmd, args = line[0], line[1:]
            if cmd in self.__commands__:
                func = self.__commands__.get(cmd)
                res = func(*args)
                if res:
                    print(res)
            else:
                self.__commands__.help()
