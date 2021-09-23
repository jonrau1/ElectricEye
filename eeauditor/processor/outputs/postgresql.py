import boto3
import os
import psycopg2 as psql
from processor.outputs.output_base import ElectricEyeOutput


@ElectricEyeOutput
class PostgresProvider(object):
    __provider__ = "postgres"

    def __init__(self):
        ssm = boto3.client("ssm")
        rds = boto3.client("rds")

        try:
            psqlRdsDbArn = os.environ["PSQL_RDS_DB_ARN"]
        except Exception as e:
            if str(e) == '"PSQL_RDS_DB_ARN"':
                psqlRdsDbArn = "placeholder"
            else:
                print(e)
        try:
            psqlRdsPwSsmParamName = os.environ["PSQL_RDS_PW_SSM_PARAM_NAME"]
        except Exception as e:
            if str(e) == '"PSQL_RDS_PW_SSM_PARAM_NAME"':
                psqlRdsPwSsmParamName = "placeholder"
            else:
                print(e)
        try:
            eePsqlDbName = os.environ["ELECTRICEYE_POSTGRESQL_DB_NAME"]
        except Exception as e:
            if str(e) == '"ELECTRICEYE_POSTGRESQL_DB_NAME"':
                eePsqlDbName = "placeholder"
            else:
                print(e)

        if (psqlRdsDbArn or psqlRdsPwSsmParamName or eePsqlDbName) == "placeholder":
            print('Either the required RDS Information was not provided, or the "placeholder" values were kept')
        else:
            # Retrieve and Decrypt DB PW from SSM
            psqlDbPw = ssm.get_parameter(Name=psqlRdsPwSsmParamName, WithDecryption=True)
            # Get endpoint and username from RDS API
            rdsInfo = rds.describe_db_instances(DBInstanceIdentifier=psqlRdsDbArn)["DBInstances"][0]
            psqlUsername = str(rdsInfo["MasterUsername"])
            dbEndpoint = str(rdsInfo["Endpoint"]["Address"])
            dbPort = str(rdsInfo["Endpoint"]["Port"])

            print('Connection host for Postgres: ' + dbEndpoint)

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
                
                '''# Drop Table - only do this if needed
                cursor.execute("""DROP TABLE IF EXISTS electriceye_findings""")'''
                
                # Create a new table for the ElectricEye findings. ID will be the Primary Key, all other elements will be parsed as text
                cursor.execute("""CREATE TABLE IF NOT EXISTS electriceye_findings( schemaversion TEXT, id TEXT PRIMARY KEY, awsaccountid TEXT, productarn TEXT, generatorid TEXT, types TEXT, firstobservedat TEXT, createdat TEXT, updatedat TEXT, severitylabel TEXT, confidence TEXT, title TEXT, description TEXT, remediationtext TEXT, remediationurl TEXT, resourcetype TEXT, resourceid TEXT, resourceregion TEXT, resourcepartition TEXT, compliancestatus TEXT, workflowstatus TEXT, recordstate TEXT);""")

                '''# This is to check all of the created Tables for T-shooting. Or just use psql CLI / pgAdmin4 to check the DB
                cursor.execute("select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';")
                print(cursor.fetchall())'''

                for finding in findings:
                    # Basic parsing of ASFF to prepare for INSERT into PSQL
                    schemaversion = str(finding['SchemaVersion'])
                    id = str(finding['Id'])
                    awsaccountid = str(finding['AwsAccountId'])
                    productarn = str(finding['ProductArn'])
                    generatorid = str(finding['GeneratorId'])
                    types = str(finding['Types'][0])
                    firstobservedat = str(finding['FirstObservedAt'])
                    createdat = str(finding['CreatedAt'])
                    updatedat = str(finding['UpdatedAt'])
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

                    cursor.execute("INSERT INTO electriceye_findings (schemaversion, id, awsaccountid, productarn, generatorid, types, firstobservedat, createdat, updatedat, severitylabel, confidence, title, description, remediationtext, remediationurl, resourcetype, resourceid, resourceregion, resourcepartition, compliancestatus, workflowstatus, recordstate) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);", (schemaversion, id, awsaccountid, productarn, generatorid, types, firstobservedat, createdat, updatedat, severitylabel, confidence, title, description, remediationtext, remediationurl, resourcetype, resourceid, resourceregion, resourcepartition, compliancestatus, workflowstatus, recordstate))

                # close communication with the postgres server (rds)
                cursor.close()
                # commit the changes
                engine.commit()

            except psql.OperationalError:
                print("Cannot connect to PostgreSQL! Review your Security Group settings and/or information provided to connect")
            except Exception:
                print("Another exception found " + Exception)
        else:
            raise ValueError("Missing credentials or database parameters")