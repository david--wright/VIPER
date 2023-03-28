from pymongo import MongoClient
import keyring
def get_database():
  service_id = "VPEngine"
  username = "wrightd"  
  password = keyring.get_password(service_id, username)
  # Provide the mongodb atlas url to connect python to mongodb using pymongo
  CONNECTION_STRING = "mongodb+srv://{}:{}@vulnerabilityprediction.5iuxtrr.mongodb.net/?retryWrites=true&w=majority".format(username,password)
 
  # Create a connection using MongoClient. You can import MongoClient or use pymongo.MongoClient
  client = MongoClient(CONNECTION_STRING)
 
  # Create the database for our example (we will use the same database throughout the tutorial
  return client['VulnerabilityPredictionEngine']
  
# This is added so that many files can reuse the function get_database()
if __name__ == "__main__":   
  
  # Get the database
  dbname = get_database()
  print (dbname)