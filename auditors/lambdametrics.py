import boto3
import time

lambda_client = boto3.client('lambda')
cloudwatch_client = boto3.client('cloudwatch')

response = lambda_client.list_functions()
functions = response['Functions']

def function_expiration_check():
    for function in functions:
        Function_Name = str(function['FunctionName'])
        metric_response = cloudwatch_client.get_metric_data(
            MetricDataQueries = [{'Id': 'm1',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/Lamda',
                    'MetricName': 'Invocations',
                    'Dimensions': [
                        {
                            'Name': 'FunctionName',
                            'Value': Function_Name
                        },
                    ]
                },
                'Period': 300,
                'Stat': 'SampleCount',
            }}],
            StartTime = time.time() - 30*24*60*60,
            EndTime = time.time()
        )
        print(metric_response)
        

function_expiration_check()



