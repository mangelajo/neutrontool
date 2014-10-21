class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    color_mat = {'header':HEADER ,'blue':BLUE, 'green':GREEN ,
                 'warning':WARNING ,'fail':FAIL}
    @staticmethod
    def color(color, string):
        return Colors.color_mat.get(color,Colors.ENDC) + string + Colors.ENDC


color = Colors.color
