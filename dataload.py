import pandas as pd
import pickle
from pathlib import Path
from dbconn import get_database
import pymongo
from pathvalidate import sanitize_filepath

# Configuration Values
years_to_fetch=20
CVEDict = {}

def fetch_cves(brand, product, version, debug=False):
    if '{}-{}-{}'.format(brand,product,version) not in CVEDict:
        filePath=sanitize_filepath("data/{}/{}/{}.p".format(brand,product,version))
        CVEPickle = Path(filePath)
        if CVEPickle.is_file():
            if debug:
                print ("Fetching {}-{}-{} from Pickle".format(brand, product, version))
            CVEDict['{}-{}-{}'.format(brand,product,version)] = loadData(CVEPickle)
        else:
            if debug:    
                print ("Not Fetching {}-{}-{} from NVD".format(brand, product, version))            
    return CVEDict['{}-{}-{}'.format(brand,product,version)]

def load_cves(brand, product, version_limit=None, sort=1, upload=False, debug=False):
    db=get_database()
    cpe_targets = db["cpe_targets"]
    versionsFullList = []
    df_vuln_detail = None
    for cpe_target in cpe_targets.find({"$and": [{"brand" : brand}, {"product": product}]}).limit(version_limit):
        version = cpe_target["version"]
        if debug:
            print (version)
        cve_coll = db['cve']
        cpe_cve_coll = db['cpe_cve']
        cve_dict = cve_coll.find({"$and": [{"brand" : brand}, {"product": product}, {"version": version}]})
        cve_df = pd.DataFrame(cve_dict)
        if cve_df.empty:    
            if debug:
                print ("...Fetching")
            cveList = fetch_cves(brand, product, version, debug)
            df_vuln_version = pd.DataFrame.from_records({
                                    "brand": brand,
                                    "product": product,
                                    "version": version,
                                    "id":cve.id,
                                    "score":cve.score[1],
                                    "score_text":cve.score[2]} 
                                    for cve in cveList)
            if not df_vuln_version.empty:
                cpe_cve_df=df_vuln_version[['brand','product','version','id']].copy() 
                cve_coll_df=df_vuln_version[['id',"score",'score_text']].copy()
                vuln_detail_dict = cve_coll_df.to_dict(orient="records")
                if upload:
                    try:
                        cve_coll.insert_many(vuln_detail_dict)
                    except pymongo.errors.BulkWriteError as e:
                        pass
                    cpe_cve_dict= cpe_cve_df.to_dict(orient="records")
                    try:
                        cpe_cve_coll.insert_many(cpe_cve_dict)
                    except pymongo.errors.BulkWriteError as e:
                        pass
        if df_vuln_detail is not None:
            df_vuln_detail = pd.concat([df_vuln_detail, df_vuln_version])
        else:
            df_vuln_detail = df_vuln_version
    return df_vuln_detail

def loadData(name):
    return pickle.load(open(name, "rb"))

def load_vulerability_history():
    return loadData("data/vuln_hist.p")
