import json

def is_FP(line):
    comman_fp = ["http://localhost/","http://127.0.0.1","com.google", "com.amazonaws", "io.fabric", "kotlin.", "com.mixpanel", "com.microsoft", "org.apache", "com.facebook", "com.crashlytics", "okhttp3.", "com.dropbox", "androidx.", "com.crashlytics"]
    for fp in comman_fp:
        if fp in line:
            return True
    return False


if __name__ == '__main__':
    tags = ['Found broken crypto schemes', 'Found broken hash functions', 'Used constant keys in code',
            'Uses untrusted TrustManager', 'Used export grade public Key', 'Uses untrusted HostNameVerifier',
            'Used HTTP Protocol', 'Used < 1000 iteration for PBE', 'Found constant salts in code',
            'Found constant IV in code', 'Found predictable seeds in code', 'Does not manually verify the hostname',
            'Untrused PRNG', 'Used Predictable KeyStore Password']
    detail_results = {}
    coarse_results = {}
    app_name = ''
    with open('./new_result.log', 'r') as f:
        blocks=f.read().split('=======================================\n')
        new_blocks = []
        for i in blocks:
            if i != '':
                if i.startswith("***Violated Rule 13:"):
                    if not is_FP(i):
                        new_blocks.append(i)
                else:
                    new_blocks.append(i)
        # print(new_blocks)
        for line in new_blocks:
            if line.startswith('Analyzing APK:'):
                if app_name:
                    detail_results[app_name] = detail_errors
                if line == 'Analyzing APK:':
                    break
                app_name = line.split(':')[1].split('\n')[0].strip()
                detail_errors = []
            if app_name and line.startswith('***Violated Rule'):
                rule = line[17:].split(':', 1)
                rule_code = rule[0].strip()
                rule_disc = rule[1].strip()
                if rule_code == '7':
                    urls_str = rule_disc.split(':', 1)[1].split('\n')[0].strip()
                    urls_nofp = []
                    urls_list = json.loads(urls_str)
                    for i in urls_list:
                        if not is_FP(i):
                            urls_nofp.append(i)
                    if len(urls_nofp) == 0:
                        continue
                    rule_disc = "Unencrypted Traffic:"+", ".join(urls_nofp)
                if rule_code == '2':
                    urls_list = rule_disc.split('\n', 1)[1].split('}, ')
                    urls_nofp = []
                    for i in urls_list:
                        if not is_FP(i):
                            urls_nofp.append(i)
                    if len(urls_nofp) == 0:
                        continue
                    rule_disc = rule_disc.split('\n', 1)[0]+":"+", ".join(urls_nofp)
                    # print(rule_disc)
                if rule_code == '1':
                    urls_list = rule_disc.split('\n', 1)[1].split('}, ')
                    urls_nofp = []
                    for i in urls_list:
                        if not is_FP(i):
                            urls_nofp.append(i)
                    if len(urls_nofp) == 0:
                        continue
                    rule_disc = rule_disc.split('\n', 1)[0]+":"+", ".join(urls_nofp)
                    # print(rule_disc)
                if rule_code == '3':
                    urls_list = rule_disc.split('\n', 1)[1].split('}, ')
                    urls_nofp = []
                    for i in urls_list:
                        if not is_FP(i):
                            urls_nofp.append(i)
                    if len(urls_nofp) == 0:
                        continue
                    rule_disc = rule_disc.split('\n', 1)[0]+":"+", ".join(urls_nofp)
                    # print(rule_disc)
                if rule_code == '12' or rule_code == '4':
                    if is_FP(rule_disc):
                        continue
                detail_error = {rule_code: rule_disc}
                detail_errors.append(detail_error)
    with open('remove_fp1.log','w') as r:
        for k in detail_results.keys():
            r.write(k+"\n")
            for weak in detail_results[k]:
                for i in weak.keys():
                    r.write(weak[i] + "\n")
            r.write("\n")
