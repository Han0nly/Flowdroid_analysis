import json
from collections import OrderedDict

import xmltodict
import os
from settings import sinks_categories, sources_categories


# class FDAnalysis:
#     def __init__(self):

def leak_category(found):
    sink = 'none'
    for category in sinks_categories.keys():
        for sink_term in sinks_categories[category]:
            if sink_term.lower() in found['Sink']['@Method'].lower() or sink_term.lower() in found['Sink'][
                '@Statement'].lower():
                sink = category
                break
        if sink != 'none':
            break

    sources = []
    if isinstance(found['Sources']['Source'], OrderedDict):
        signal = 0
        for category in sources_categories.keys():
            for source_term in sources_categories[category]:
                if source_term.lower() in found['Sources']['Source']['@Method'].lower() or source_term.lower() in \
                        found['Sources']['Source']['@Statement'].lower():
                    signal = 1
                    sources.append(category)
                    break
            if signal == 1:
                break
    elif isinstance(found['Sources']['Source'], list):
        for source in found['Sources']['Source']:
            signal = 0
            for category in sources_categories.keys():
                for source_term in sources_categories[category]:
                    if source_term.lower() in source['@Method'].lower() or source_term.lower() in source[
                        '@Statement'].lower():
                        sources.append(category)
                        break
                if signal == 1:
                    break
                # components 41.4%
                # logs =
                # 网络13
    if sink == 'none':
        return 'none'
    if len(sources) == 0:
        return 'none'
    return ('%s:%s' % (set(sources), sink))


if __name__ == '__main__':
    results = {}
    for root, dirs, files in os.walk('./FDA_Flowdroid'):
        print("一共有多少个文件：", len(files))
        for file in files:
            if file[-3:] == "xml":
                file_fullpath = os.path.join(root, file)
                with open(file_fullpath) as f:
                    xml_str = f.readline()
                    # 将xml的字符串解析为字典类型
                    jsonstr = xmltodict.parse(xml_str)
                    results[file[:-4]] = jsonstr
    readable_result = {}
    for app in results.keys():
        # print(app)
        single_readable = []
        all_result = results[app]['DataFlowResults']
        if 'Results' in all_result.keys():
            result_list = all_result['Results']['Result']
            if isinstance(result_list, OrderedDict):
                leak = leak_category(result_list)
                if leak != 'none':
                    single_readable.append(leak)
            elif isinstance(result_list, list):
                for found in result_list:
                    leak = leak_category(found)
                    if leak != 'none':
                        single_readable.append(leak)

        if len(single_readable) != 0:
            readable_result[app] = list(set(single_readable))

    print(readable_result)

    statistics_sources = {}
    for i in readable_result.keys():
        already = []
        for leak in readable_result[i]:
            items = leak.split(':')[0][2:-2]
            for item in items.split(','):
                item = item.strip().strip('\'')
                if item in already:
                    continue
                else:
                    already.append(item)
                    if item in statistics_sources.keys():
                        statistics_sources[item] = statistics_sources[item] + 1
                    else:
                        statistics_sources[item] = 1
    print('These kinds of information are leaked:', statistics_sources)

    statistics_sinks = {}
    for i in readable_result.keys():
        already = []
        for leak in readable_result[i]:
            item = leak.split(':')[1]
            if item in already:
                continue
            else:
                already.append(item)
                if item in statistics_sinks.keys():
                    statistics_sinks[item] = statistics_sinks[item] + 1
                else:
                    statistics_sinks[item] = 1
    print('Sensitive Information leaks through these way:', statistics_sinks)

    # statistics_logs = []
    # for i in readable_result.keys():
    #     for leak in readable_result[i]:
    #         item = leak.split(':')[1]
    #         if item == 'logs':
    #             source = leak.split(':')[0][2:-2]
    #             for i in source.split(','):
    #                 i = i.strip().strip('\'')
    #                 if i in statistics_logs:
    #                     continue
    #                 else:
    #                     statistics_logs.append(i)
    #
    # print('Logs leaks these information:', statistics_logs)
