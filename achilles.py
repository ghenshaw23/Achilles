#!/usr/bin/env python3

# Allows us to access command line arguments
import argparse
# Allows us to validate URLs
import validators
import requests
# Allows us to import yaml files for configuration
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment
 
parser = argparse.ArgumentParser(description='The Achilles Vulnerability Analyzer Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="The URL of the HTML to analyze")
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args()

config = {'forms': True, 'comments': True, 'passwords': True}

if(args.config):
  print('Using config file: ' +args.config)
  config_file = open(args.config, 'r')
# The yaml load function takes in an input stream and converts it into a python object as long as it's valid yaml
  config_from_file = yaml.load(config_file)
  if(config_from_file):
    config = { **config, **config_from_file }

report = ''

url = args.url

if(validators.url(url)):
  result_html=requests.get(url).text
# Here we construct the Beautiful Soup object (parsed_html)
  parsed_html=BeautifulSoup(result_html, 'html.parser')
# We can access objects within parsed_html by using .title, .head, .body, .form, etc
#  print(parsed_html.form)

  forms			 = parsed_html.find_all('form')
  comments		 = parsed_html.find_all(string=lambda text:isinstance(text,Comment))
  password_inputs	 = parsed_html.find_all('input', { 'name' : 'password'})

  if(config['forms']):
    for form in forms:
      if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
        report += 'Form Issue: Insecure form action ' + form.get('action') + ' found in document\n'

  if(config['comments']):
    for comment in comments:
      if(comment.find('key: ') > -1):
        report += 'Comment Issue: Key is found in HTML comments, please remove\n'     

  if(config['passwords']):  
    for password_input in password_inputs:
      if(password_input.get('type') != 'password'):
        report += 'Input Issue: Plaintext password input found. Please change to password type input\n'

else:
  print("Invalid URL")

if (report == ''):
  report += 'HTML document secure'
else:
  header = '\nVulnerability report\n********************\n\n'
  report = header + report

if(args.output):
  f = open(args.output, 'w')  
  f.write(report)
  f.close
  print('Report saved to: ' + args.output)
