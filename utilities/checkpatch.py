    global __errors, __warnings
line_length_blacklist = ['.am', '.at', 'etc', '.in', '.m4', '.mk', '.patch',
                         '.py']
leading_whitespace_blacklist = ['.mk', '.am', '.at']
     'match_name':
     lambda x: not any([fmt in x for fmt in line_length_blacklist]),
     'check': lambda x: line_length_check(x),
     'print': lambda: print_warning("Line length is >79-characters long")},
     'match_name':
     lambda x: not any([fmt in x for fmt in leading_whitespace_blacklist]),
    {'regex': '(.c|.h)(.in)?$', 'match_name': None,
    {'regex': '(.c|.h)(.in)?$', 'match_name': None,
    {'regex': '(.c|.h)(.in)?$', 'match_name': None,
     lambda: print_error("Inappropriate spacing in pointer declaration")}
    {'regex': '(.c|.h)(.in)?$',
            check['print']()
    scissors = re.compile(r'^[\w]*---[\w]*')
    is_signature = re.compile(r'((\s*Signed-off-by: )(.*))$',
    is_co_author = re.compile(r'(\s*(Co-authored-by: )(.*))$',
            parse = 2
        if parse == 1:
                parse = parse + 1
        elif parse == 0:
            if scissors.match(line):
                parse = parse + 1
                signatures.append(m.group(3))
                co_authors.append(m.group(3))
        elif parse == 2:
    global __warnings, __errors, total_line
    else:
        optlist, args = getopt.getopt(args, 'bhlstf',
                                       "skip-trailing-whitespace"])
            print('== Checking %s ("%s") ==' % (revision[0:12], name))
        print('== Checking "%s" ==' % filename)