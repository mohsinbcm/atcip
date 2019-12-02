#import matplotlib.pyplot as plt
import requests
#from PIL import Image
from io import BytesIO
import json
import re
import dateparser

def process(image_path):
    endpoint = "https://atcip-ocr.cognitiveservices.azure.com/"
    subscription_key = "05d7ced953b440719b5252ece68177da"

    analyze_url = endpoint + "vision/v2.1/ocr"
    # Read the image into a byte array
    image_data = open(image_path, "rb").read()
    headers = {'Ocp-Apim-Subscription-Key': subscription_key,
            'Content-Type': 'application/octet-stream'}
    params = {'language': 'unk', 'detectOrientation': 'true'}
    response = requests.post(
        analyze_url, headers=headers, params=params, data=image_data)
    response.raise_for_status()
    return parse(response.json())

def parse(analysis):
    # Extract the word bounding boxes and text.
    lines =[]
    line_infos = [region["lines"] for region in analysis["regions"]]
    for line in line_infos:
        for word_metadata in line:
            word_infos = []
            for word_info in word_metadata["words"]:
                word_infos.append(word_info['text'])
            lines.append(' '.join(word_infos))
    policy_line = None
    dates_line = None
    sum_insured_line = None
    interest_line = None
    premium_line = None
    cordinates = None
    for no, line in enumerate(lines):
        if all(x in line.lower() for x in ['policy', 'no']):
            policy_line = no 
        if all(x in line.lower() for x in ['from', 'to']):
            dates_line = no 
        if all(x in line.lower() for x in ['sum','insured','rs.']):
            sum_insured_line = no+1
        if all(x in line.lower() for x in ['liabilities', '%']):
            interest_line = no
        if all(x in line.replace(' ','').lower() for x in ['premium', '(rs)']):
            premium_line = no+1
        if all(x in line.replace(' ','').lower() for x in ['description', 'property']):
            next_indx = None
            for y in range(no, len(lines)):
                if all(xx in lines[y].lower() for xx in ['sum','insured','rs.']):
                    next_indx = y
                    break
            cordinates = ' '.join(lines[no: next_indx])
            
    pairs = (re.findall(r'\[\(.*\)\]', cordinates)[0]).strip(')]').strip('[(')
    pairs = [x for x in pairs.split(') (')]
    policy_no = lines[policy_line].split(':')[-1].strip()
    dates = lines[dates_line].split(':')[-1]

    regex_start_date = r'(From\s*(?:\d+/\d+/\d+))'
    start_date = re.findall(regex_start_date,dates,re.IGNORECASE)[0]
    start_date = start_date.replace('From','')
    start_date = start_date.strip(' ')
    regex_end_date = r'(to\s*(?:\d+/\d+/\d+))'
    end_date = re.findall(regex_end_date,dates,re.IGNORECASE)[0]
    end_date = end_date.replace('to','')
    end_date = end_date.strip(' ')

    sum_insured = re.findall(r'\d* ',lines[sum_insured_line])[0]
    interest = re.findall(r'\d+.\d*%', lines[interest_line])[0]
    interest = float(interest.replace('%',''))
    premium = float(re.findall(r'(\d*)',lines[premium_line])[4])
    return {'policy':policy_no,
            'dates':[dateparser.parse(start_date, settings={'DATE_ORDER': 'DMY'}),dateparser.parse(end_date, settings={'DATE_ORDER': 'DMY'})],
            'sum_insured':sum_insured,
            'premium': premium,
            'interest': interest,
            'coordinates': pairs
    }

if __name__=="__main__":
    analysis = None
    with open('data.txt') as json_file:
        analysis = json.load(json_file)
    print(parse(analysis))