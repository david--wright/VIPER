
import pandas as pd
import nvdlib 
import datetime
import pickle
import glob
from pathlib import Path
from dataload import fetch_cves
from dbconn import get_database

import pymongo
import keyring

# Configuration Values
service_id = "VPEngine"
key_name = "NVDKEY"  
NVDKEY=  keyring.get_password(service_id, key_name)
descLang="en"
years_to_fetch=20
CVEDict = {}

def create_collections():
    db=get_database()
    cve_coll = db['cve']
    cpe_cve_coll = db['cpe_cve']
    cve_coll.create_index("id", unique=True)
    cpe_cve_coll.create_index([("cpe_id", 1), ('cves', 1)], unique=True)

def create_cpe_cve_corralation():
    db=get_database()
    cpe_cve = db['cpe_cve']
    cpe_cve.create_index([("cpe_id", 1), ('cve', 1)], unique=True)
    cpe_targets = db["cpe_targets"]
    cpe_cve_list = []
    cpe_load_count = 0
    for cpe in cpe_targets.find().sort("{_id:1}"):
        cve_coll = db['cve']
        if not cpe_load_count % 1000:
            print ("Loaded {}/271795".format(cpe_load_count))
        cves = fetch_cves(cpe['brand'], cpe['product'], cpe['version'])
        cpe_load_count += 1
        if cves:
            for cve in cves:
                cpe_cve_list.append({"cpe_id" : cpe['_id'],
                                "cve" : cve.id})
        CVEDict['{}-{}-{}'.format(cpe['brand'], cpe['product'], cpe['version'])] = False
    try:
        print ("Loading data to mongodb")
        cpe_cve.insert_many(cpe_cve_list, ordered=False)
    except pymongo.errors.DuplicateKeyError:
        pass

def create_vulnerability_history():
    db=get_database()
    cpe_history = {}
    cpe_counts = {}
    cpe_cve = db['cpe_cve']
    cpe_targets = db["cpe_targets"]        
    cpe_view= [{'$lookup': {
            'from': 'cpe_cve',
            'localField': '_id',
            'foreignField': 'cpe_id',
            'as': 'cpe_cves'}
            },
            {'$unwind': '$cpe_cves'},
            {'$lookup': {
                'from': 'cve',
                'localField': 'cpe_cves.cve',
                'foreignField': 'id',
                'as': 'cpe_cves.data'

            }},
            {'$project':{
                'brand': 1,
                'product': 1,
                'version': 1,
                'cpe_cves.cve': 1,
                'cpe_cves.data.lastModified': 1,
                'cpe_cves.data.score': 1
            }}
        ]
    for cpe in (cpe_targets.aggregate(cpe_view)):
        cpe_name = (cpe['brand'], cpe['product'])
        try:
            cve_year = cpe['cpe_cves']['data'][0]['lastModified'][0:4]
            cve_score = cpe['cpe_cves']['data'][0]['score']
        except:
            continue
        if cpe_name not in cpe_history:
            cpe_history[cpe_name] = [0] * 4
            cpe_counts[cpe_name] = [int(0)] * 6
        if int(cve_year) > 2019:    
            cpe_history[cpe_name][int(cve_year)-2020] += cve_score
        if cve_year == "2022":
            if cve_score > 9:
                cpe_counts[cpe_name][3] += 1
            elif cve_score > 7:
                cpe_counts[cpe_name][2] += 1
            elif cve_score > 4:
                cpe_counts[cpe_name][1] += 1
            else:
                cpe_counts[cpe_name][0] += 1
    high = (None, 0)
    low = (None, 100)
    for name, count in cpe_counts.items():
        count_total = sum([int(x) for x in count])
        if count_total:
            count[4] = count[3]/count_total*100
        else:
            count[4] = 0
        if count[4] > high[1]:
            high = (name, count[4])
        if count[4] < low[1]:
            low = (name, count[4])
    print (low,high)
    for name, history in cpe_history.items():
        if history[2] > 500 and cpe_counts[name][4] > 10:
            cpe_counts[name][5] = "CRITICAL"
        elif history[2] > 500 or cpe_counts[name][4] > 10:
            cpe_counts[name][5] = "HIGH"
        elif history[2] > 100 or cpe_counts[name][4]:
            cpe_counts[name][5] = "MEDIUM"
        else:
            cpe_counts[name][5] = "LOW"
        history += cpe_counts[name]
        del history [3]
    
    pickle.dump(cpe_history, open("data/vuln_hist.p", "wb"))
    return cpe_history

def get_cpe(cve):
    try:
        return [item.criteria for item in cve.cpe
                                if item.vulnerable==True]
    except AttributeError:
        return None  

def loadData(name):
    return pickle.load(open(name, "rb"))

def retrive_cpe_list():
    now =  datetime.datetime.now()
    for i in range(years_to_fetch):
        start = now - datetime.timedelta(days=(120*i+1))
        end = now - datetime.timedelta(days=(120*(i)))
        r = nvdlib.searchCPE(lastModStartDate=start, lastModEndDate=end)
        for CPE in r:
            print(CPE.cpeName)
        cpeList = [cpe.cpeName for cpe in r]
        print (cpeList)
        pickle.dump(cpeList, open("cpeList.p", "wb"))
        pickle.dump(r, open("cpe.p", "wb"))

def retrive_cves():
    now =  datetime.datetime.now()-datetime.timedelta(days=(16))
    for i in range(3*years_to_fetch):
        print("Cycle {}".format(i))
        start = now - datetime.timedelta(days=(120*(i+1)))
        end = now - datetime.timedelta(days=(120*(i)))
        filePath = "data/cve{}-{}.p".format(start.strftime("%b%Y"),end.strftime("%b%Y"))
        CVEPickle = Path(filePath)
        print("Start Query {}-{}".format(start.strftime("%b%Y"),end.strftime("%b%Y")))
        if CVEPickle.is_file():
            print("Already Exists {}-{}".format(start.strftime("%b%Y"),end.strftime("%b%Y")))  
            continue
        cveList = nvdlib.searchCVE(delay=2, lastModStartDate=start, lastModEndDate=end, key=NVDKEY)
        pickle.dump(cveList, open(filePath, "wb"))
        print("End Query {}-{} : {} records".format(start.strftime("%b%Y"),end.strftime("%b%Y"), len(cveList)))

def upload_cpe():
    cpeFileList = glob.glob("data/cpeNames*")
    cpeNameList = []
    for file in cpeFileList:
        cpeNameList += loadData(file)

    cpeFormatted=[cpe.split(':')[3:6] for cpe in cpeNameList]
    cpeBrands=sorted(set([cpe[0] for cpe in cpeFormatted]))
    cpeDB=[{"brand" : cpe[0],
        "product" : cpe[1],
        "version" : cpe[2]}
        for cpe in cpeFormatted
    ]
    db=get_database()
    cpe_targets = db["cpe_targets"]
    cpe_targets.insert_many(cpeDB)
    cpe_df = pd.DataFrame(cpe_targets.find())
    print(cpe_df)

def upload_cve():
    db=get_database()
    cve_coll = db['cve']
    cve_coll.create_index("id", unique=True)
    cve_list = []
    now =  datetime.datetime.now()-datetime.timedelta(days=(16))
    for i in range(3*years_to_fetch):
        # if not i%5:
        #     print("Sleeping for 10")
        #     sleep(10)
        errors=0
        print("Cycle {}".format(i))
        start = now - datetime.timedelta(days=(120*(i+1)))
        end = now - datetime.timedelta(days=(120*(i)))
        print("Start Query {}-{}".format(start.strftime("%b%Y"),end.strftime("%b%Y")))
        cve_list = pickle.load(open("data/cve{}-{}.p".format(start.strftime("%b%Y"),end.strftime("%b%Y")), "rb"))
        print("End Query {}-{} : {} records".format(start.strftime("%b%Y"),end.strftime("%b%Y"), len(cve_list)))
        df_vuln_version = pd.DataFrame.from_records({
                                        "id":cve.id,
                                        "sourceIdentifier":cve.sourceIdentifier,
                                        "published":cve.published,
                                        "lastModified":cve.lastModified,
                                        "vulnStatus":cve.vulnStatus,
                                        "descriptions":[description.value for description in cve.descriptions
                                                        if description.lang==descLang],
                                        "url":cve.url,
                                        "cpe":get_cpe(cve),
                                        "score":cve.score[1],
                                        "score_text":cve.score[2]} 
                                        for cve in cve_list)
        vuln_detail_dict = df_vuln_version.to_dict(orient="records")
        try:
            cve_coll.insert_many(documents=vuln_detail_dict, ordered=False)
        except pymongo.errors.BulkWriteError as e:
            errors += 1
        print ("Errors: {}".format(errors))



if __name__ == "__main__":
    create_collections()
    retrive_cpe_list()
    upload_cpe()
    retrive_cves()
    upload_cve()
    create_cpe_cve_corralation()
    create_vulnerability_history()