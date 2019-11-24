#import matplotlib.pyplot as plt
import requests
#from PIL import Image
from io import BytesIO
import json


endpoint = "https://westcentralus.api.cognitive.microsoft.com/"
subscription_key = "325e8590e56d4d4fb06765dda5053b35"

analyze_url = endpoint + "vision/v2.1/ocr"

# Set image_path to the local path of an image that you want to analyze.
image_path = "uploads/15746175048585145901619869251255.jpg"

# Read the image into a byte array
image_data = open(image_path, "rb").read()
# image = Image.open(BytesIO(image_data))
# print(image.size)
# new_Size = (int(image.size[0]/2), int(image.size[1]/2))
# image = image.resize(new_Size,Image.ANTIALIAS)
# # image.save(image_path,optimize=True,quality=95)
# exit()
# image_data = open(image_path, "rb").read()
headers = {'Ocp-Apim-Subscription-Key': subscription_key,
           'Content-Type': 'application/octet-stream'}
params = {'language': 'unk', 'detectOrientation': 'true'}
response = requests.post(
    analyze_url, headers=headers, params=params, data=image_data)
# response.raise_for_status()

# The 'analysis' object contains various fields that describe the image. The most
# relevant caption for the image is obtained from the 'description' property.
analysis = response.json()
print(json.dumps(analysis, indent=4, sort_keys=True))
image_caption = analysis['regions'][2]['lines'][2]['words'][3]['text']
print(image_caption)
image_caption = analysis['regions'][5]['lines'][1]['words'][0]['text']
print (image_caption)
# image_caption = analysis["description"]["captions"][0]["text"].capitalize()

# Display the image and overlay it with the caption.
# plt.imshow(image)
# plt.axis("off")
# _ = plt.title(image_caption, size="x-large", y=-0.1)