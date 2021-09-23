import boto3
import os
from botocore import exceptions
import psycopg2 as psql
from processor.outputs.output_base import ElectricEyeOutput


@ElectricEyeOutput
class PostgresProvider(object):
    __provider__ = "postgres"

    def __init__(self):
        ssm = boto3.client("ssm")
        # Username
        try:
            psqlUsername = os.environ["POSTGRES_USERNAME"]
        except Exception as e:
            if str(e) == '"POSTGRES_USERNAME"':
                psqlUsername = "placeholder"
            else:
                print(e)
        # DB Name
        try:
            eePsqlDbName = os.environ["ELECTRICEYE_POSTGRESQL_DB_NAME"]
        except Exception as e:
            if str(e) == '"ELECTRICEYE_POSTGRESQL_DB_NAME"':
                eePsqlDbName = "placeholder"
            else:
                print(e)
        # DB Endpoint
        try:
            dbEndpoint = os.environ["POSTGRES_DB_ENDPOINT"]
        except Exception as e:
            if str(e) == '"POSTGRES_DB_ENDPOINT"':
                dbEndpoint = "placeholder"
            else:
                print(e)
        # DB Port
        try:
            dbPort = os.environ["POSTGRES_DB_PORT"]
        except Exception as e:
            if str(e) == '"POSTGRES_DB_PORT"':
                dbPort = "placeholder"
            else:
                print(e)
        # Secret Parameter
        try:
            psqlRdsPwSsmParamName = os.environ["POSTGRES_PASSWORD_SSM_PARAM_NAME"]
        except Exception as e:
            if str(e) == '"POSTGRES_PASSWORD_SSM_PARAM_NAME"':
                psqlRdsPwSsmParamName = "placeholder"
            else:
                print(e)
        

        if (psqlUsername or eePsqlDbName or dbEndpoint or dbPort or psqlRdsPwSsmParamName) == "placeholder":
            print('Either the required RDS Information was not provided, or the "placeholder" values were kept')
            exit(2)
        else:
            # Retrieve and Decrypt DB PW from SSM
            psqlDbPw = ssm.get_parameter(Name=psqlRdsPwSsmParamName, WithDecryption=True)["Parameter"]["Value"]

            self.db_endpoint = dbEndpoint
            self.db_port = dbPort
            self.db_username = psqlUsername
            self.db_password = psqlDbPw
            self.db_name = eePsqlDbName

    def write_findings(self, findings: list, **kwargs):
        print(f"Writing {len(findings)} results to PostgreSQL")
        if self.db_endpoint and self.db_port and self.db_username and self.db_password and self.db_name:
            try:
                # Connect to DB and create a Cursor
                engine = psql.connect(
                    database=self.db_name,
                    user=self.db_username,
                    password=self.db_password,
                    host=self.db_endpoint,
                    port=self.db_port
                )
                cursor = engine.cursor()
                
                # drop previously existing tables
                cursor.execute("""DROP TABLE IF EXISTS electriceye_findings""")
                engine.commit()
                
                # Create a new table for the ElectricEye findings. ID will be the Primary Key, all other elements will be parsed as text
                cursor.execute("""CREATE TABLE IF NOT EXISTS electriceye_findings( schemaversion TEXT, findingid TEXT PRIMARY KEY, awsaccountid TEXT, productarn TEXT, generatorid TEXT, types TEXT, createdat TEXT, severitylabel TEXT, confidence TEXT, title TEXT, description TEXT, remediationtext TEXT, remediationurl TEXT, resourcetype TEXT, resourceid TEXT, resourceregion TEXT, resourcepartition TEXT, compliancestatus TEXT, workflowstatus TEXT, recordstate TEXT);""")

                for finding in findings:
                    # Basic parsing of ASFF to prepare for INSERT into PSQL
                    try:
                        awsaccountid = str(finding['AwsAccountId'])
                        schemaversion = str(finding['SchemaVersion'])
                        findingid = str(finding['Id'])
                        productarn = str(finding['ProductArn'])
                        generatorid = str(finding['GeneratorId'])
                        types = str(finding['Types'][0])
                        createdat = str(finding['CreatedAt'])
                        severitylabel = str(finding['Severity']['Label'])
                        confidence = str(finding['Confidence'])
                        title = str(finding['Title'])
                        description = str(finding['Description'])
                        remediationtext = str(finding['Remediation']['Recommendation']['Text'])
                        remediationurl = str(finding['Remediation']['Recommendation']['Url'])
                        resourcetype = str(finding['Resources'][0]['Type'])
                        resourceid = str(finding['Resources'][0]['Id'])
                        resourceregion = str(finding['Resources'][0]['Region'])
                        resourcepartition = str(finding['Resources'][0]['Partition'])
                        compliancestatus = str(finding['Compliance']['Status'])
                        workflowstatus = str(finding['Workflow']['Status'])
                        recordstate = str(finding['RecordState'])
                    except Exception:
                        pass

                    cursor.execute("INSERT INTO electriceye_findings (schemaversion, findingid, awsaccountid, productarn, generatorid, types, createdat, severitylabel, confidence, title, description, remediationtext, remediationurl, resourcetype, resourceid, resourceregion, resourcepartition, compliancestatus, workflowstatus, recordstate) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);", (schemaversion, findingid, awsaccountid, productarn, generatorid, types, createdat, severitylabel, confidence, title, description, remediationtext, remediationurl, resourcetype, resourceid, resourceregion, resourcepartition, compliancestatus, workflowstatus, recordstate))

                # close communication with the postgres server (rds)
                cursor.close()
                # commit the changes
                engine.commit()

            except psql.OperationalError:
                print("Cannot connect to PostgreSQL! Review your Security Group settings and/or information provided to connect")
                exit(2)
            except Exception:
                print("Another exception found " + Exception)
                exit(2)
        else:
            raise ValueError("Missing credentials or database parameters")