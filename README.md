# IST-303-Team-B-Project: Cuisine 'n COVID19
***
## PROJECT REQUIREMENTS:
In this project you are required to implement a GUI application in Python 3. The GUI app interfaces the user to an underlying data store. The project should be completed using the agile principles articulated in Pilone & Miles. Make sure to meet with your instructor as regularly as you require to ensure that the project is scoped appropriately – neither too narrowly nor too widely.
***
## Milestone 1
### Part A
---

### Product: Cuisine 'n COVID19
Orange County Restaurant COVID19-compliant
Restaurants map in Orange County in COVID19 situation

**Concept:** A website that allows you to look for restaurants currently open during the pandemic, what services are being provided, and how they are enforcing COVID regulations. We will filter out information from Twitter and Yelp posts and reviews to obtain information that is most relevant to our website's goal. We will create the necessary map using GIS, and create a program that points to a given location within that map using queries to extract information from Twitter using Twitter's API.


### Team member:
Dominic Lee, Vanessa Reyes, Thawachsorn Sookthai, Miles von Herrmann


### Stakeholders:
* Residents of Orange County- people looking for dining options within Orange County based on certain criteria (see above in Story).
* Restaurant owners
* Restaurant workers
* Travelers to Orange County
* People looking for employment
* County + State health officials 

### User Stories:
**As a user:**
 1. I want to look for restaurants within Orange County. What kind of services do they provide (outdoor/indoor seating, take out, delivery, curbside, social distancing, and disinfecting and sanitizing). I want to find a restaurant that matches my criteria within Orange County.
2. As a diner, I want to find restaurants near me that are COVID compliant. How are restaurants maintaining a safe and COVID compliant environment?
3. I want to see what others have said about certain restaurants.
4. I would like to see information on how restaurants have been impacted by COVID (How long have they been closed for? Are they currently open?)
5. How much seating is available at a given restaurant?
6. I would like to have the option to see restaurants that match my given criteria within a list.
7. I would like to see a login page. 
8. I would like to see a map of restaurants within Orange County.
9. I want to be able to access my account and save my searches and preferences.

### Research:

[![N|Solid](https://i.ibb.co/xF6pQzb/SafeDine.png)](https://www.ocbc.org/safedineoc-grantrecipient/)

The County of Orange announced on August,6 2020 that the launch of a new SafeDineOC COVID-Safe Restaurant Campaign to incentivize Orange County restaurants to follow California Department of Public Health (CDPH) guidance to prevent the spread of COVID-19.

Restaurant owners may apply for a $1,000 grant per Orange County restaurant location for taking steps to create a COVID-safe environment for their customers and employees. The grant will reimburse restaurants for purchases of personal protective equipment including face masks, cleaning products, employee training and costs for physical distancing of tables and chairs, as examples.

The SafeDineOC campaign is sponsored by the County of Orange and managed by Orange County Business Council (OCBC), which will handle intake and approval of all restaurant applications as well as disbursement of the $1,000 grants to restaurant owners. Through its comprehensive database of restaurants, the OC Health Care Agency will ensure the promotion of the campaign to all restaurant owners in the County.

Restaurants that apply and are approved will be added to a list of COVID-safe eateries organized by city that will be available to consumers on the SafeDineOC website. This online resource will enable the public to see which restaurants offer a safe dining experience in Orange County

“Maintaining consumer confidence in the restaurant industry is critical to helping businesses stay afloat during these challenging times,” said Supervisor Lisa Bartlett. “When customers visit a restaurant, they want to be confident that it is clean and in compliance with County health and safety guidelines,” said Bartlett. “The safety and protection of restaurant workers, and the customers they serve, is paramount to stopping the spread of COVID-19,” she said.

Finally, the OCBC (Orange County Business Council) launched the list the forefront of safely serving Orange County at https://www.ocbc.org/safedineoc-grantrecipient/

[![N|Solid](https://i.ibb.co/Qv60Qc3/Logo-2.png)](https://orangeeco.envisionconnect.com/#/pa1/search)

The Orange Health Care Agency has published the list of restaurants which has been joined the food inspection campaign. The list is contained upto 13,000 restaurants across the county. Our group extract the list which includes restaurants'name and address.
After finished extracting database manually, we examed and cleaned up data to select only restaurants.

 
### Process:
Timeline: 
* Creating map of restaurants in given area(s)
* Creating program to point to map given certain criteria
* Testing programming, fixing bugs


### Class Presentation Slides:  
Project proposal : Project Requirements Part A

[![N|Solid](https://i.ibb.co/j686cQY/googleslide.png)](https://drive.google.com/file/d/1pJJzOb0ccUWlm0MDcwRktVupkhMgKlMe/view?usp=sharing)

***  

## Part B
---

### User Stories (estimate of completion times) and decomposition into tasks:

1. I want to look for restaurants within Orange County. What kind of services do they provide (outdoor/indoor seating, take out, delivery, curbside, social distancing, and disinfecting and sanitizing). I want to find a restaurant that matches my criteria within Orange County.
*10 Days*  
**Tasks:**  
a) Extract location information and names of restaurants from Twitter API.  
b) Create queries for the different keywords(seating, take out, ...).  
c) Create interface for user/diner to search for services based on keywords(search bar,sub pages).
         
2. As a diner, I want to find restaurants near me that are COVID compliant. How are restaurants maintaining a safe and COVID compliant environment?
*3 Days*  
**Tasks:**  
a) Create additional queries, with keywords related to a restaurant being COVID compliant(from Twitter feed).  
b) Design functionality for user to be able to set search radius on the map.  
 
3. I want to see what others have said about certain restaurants.
*3 Days*  
**Tasks:**  
a) Extract data from Yelp API, to get information/restaurant reviews from the other diners regarding the restaurants in diners' queries.  
b) Create window within program specificially for Yelp, to store reviews/information about restaurants as they become available.  
         
4. I would like to see information on how restaurants have been impacted by COVID (How long have they been closed for? Are they currently open?).
*8 Days*  
**Tasks:**  
a) Pull data from Twitter API, posts from restaurants that talk about their open/closed status during pandemic.  
b) Display relevant information(in clear and consistent manner for all restaurants) found in tweets in pop-up dialogue window when user selects a certain restaurant on the map.  
         
5. How much seating is available at a given restaurant?
*2 Days*  
**Tasks:**  
a) Pull information about seating/seating capacity percentage from restaurants' twitter pages.  
b) Allow for user to query just seating information when looking up a specific restaurant.  

6. I would like to have the option to see restaurants that match my given criteria within a list.  
*2 Days*  
**Tasks:**  
a) Create a separate results box within the program -- show restaurants that match criteria user has given.  
b) Sort results by which criteria item the user entered in first.   
         
**-----Milestone 1.0-----**
 
7. I would like to see a login page.  
*4 Days*  
**Tasks:**  
a) Create landing page with GUI interface using Flask.  
b) Create interactive username and password text fields.  
         
8. I would like to see a map of restaurants within Orange County.  
*6 Days*  
**Tasks:**  
a) Embed arcgis web-map of Orange County, display all restaurants as pins on map.  
b) Create boundary for Orange county using arcpy code, drawing polygon on top of map.  
         
9.  I want to be able to access my account and save my searches and preferences.  
*9 Days*  
**Tasks:**  
a) Create user profile page -- which shows user's preferences and searches.  
b) Create a user account list, data storage location which allows diners to find people they know.  
         

### Iterations for Milestone:
**Milestone #1**
- Be able to log into program, enter in username and password 
- Be able to view and interact with map that has partial functionality 

***
## Part C
---
### Velocity
### * Milestone 1
There are 3 user stories and 6 Tasks in Milestone 1

| Task No. | Task | Days required | Hours required |
| ------ | ------ | ------ | ------ |
| **U7** | **I would like to see a login page.** | **4**| **
| 7a | Create landing page with GUI interface using Flask. | 2 | 8
| 7b | Create interactive username and password text fields. | 2 | 8
| **U8** | **I would like to see a map of restaurants within Orange County.** | **6** | **
| 8a | Embed arcgis web-map of Orange County, display all restaurants as pins on map. | 3 | 12
| 8b | Create boundary for Orange county using arcpy code, drawing polygon on top of map. | 3 | 12
| **U9** | **I want to be able to access my account and save my searches and preferences.** | **9** | **
| 9a | Create user profile page -- which shows user's preferences and searches. | 5 | 20
| 9b | Create a user account list, data storage location which allows diners to find people they know. | 4 | 16
| | Total | 19 | 76 (19x4)

Days needed = 19 days | Assume that 4 working hours per day | 4 developers --> 1 hour per team member per day

It is complicated to calculate base on task completed, then we calculate base on sum of working hours used vs number of day left.
We have calculated the velocity as below:

| Factors | Data | How to calculate |
| ------ | ------ | ------ |
| Sprint start date | 7-Oct | |
| Sprint end date | 2-Nov |  |
| Working days | 19 |  |
| Team size | 4 |  |
| Work hours per day | 1 |  |
| Total available hours | 76 | working days * team size * work hours per day |
| Average daily available hours | 4 | total available hours / working days |
| Average productivity | 80 % |  |
| Productivity hours | 60.8 | total available hours * average productivity |
| Average daily productive hours | 3.2 | productivity hours / working days |


### Burn Down Chart:
We have created the burn down calculator to input the working hours for each developer.
Please follow the link https://bit.ly/31q50o7
(Only CGU member with this link can access, but only our team can edit)

![N|Solid](https://i.ibb.co/mXpvY0p/Screen-Shot-2020-11-04-at-8-28-24-AM.png)

[![N|Solid](https://i.ibb.co/BCcyRhM/GraphJ.png)](https://bit.ly/31q50o7)


### Stand Up Meeting:
| Meeting No | Date | Detail |
| ------ | ------ | ------ |
| 1 | Sep 13 | Brainstorming, initiate the project, sharing background and identified user stories |
| 2 | Sep 15 |Finishing draft of pitch, user stories, working hour estimation, velocity and user stories, and preparation for project requirement A presentation |
| 3 | Sep 23 | Update progression and challenges |
| 4 | Oct 06 | Update milestone#1 for project requirement B and preparing the presentation |
| 5 | Oct 13 | Update progression and agree to use Flask |
| 6 | Oct 16 | Update progression and challenges, brainstorming to solve the problems |
| 7 | Oct 21 | Update progression and challenges, the list of restaurants in Orange county |
| 8 | Oct 28 | Update progression and challenges, pin map, username / password database |
| 9 | Oct 31 | Update progression and challenges, pytest and installing the packages, and prepating the project requirement C presentation |
| 10 | Nov 04 | Problem solving and preparation for M2|

### Functional and Test Code:
* Test load URL index
* Test load URL dashboard
* Test login
* Test signup

The proposed testing code:
```sh
from flask import Flask
import json
from project.Cuisine import User,LoginForm,RegisterForm

#load URL index
def test_base():
    app = Flask(__name__)
    # configure_routes(app)
    # client = app.test_client()
    ## --- Fix URL test download ----
    # url = '/'

    # response = client.get(url)

    # assert response.status_code == 200

#load URL dashboard
def test_base_dashboard():
    app = Flask(__name__)
    configure_routes(app)
    # client = app.test_client()
    # url = '/dashboard'

    # response = client.get(url)
    # assert response.status_code == 200

def test_login(app):
    with app.test_client() as c:
        c.post('/login', follow_redirects=True, dict(
            name=username,
            password=test_password
        ))
    assert flask.session['user_id'] == user_id

def test_signup(app):
    with app.test_client() as c:
        c.post('/signup', follow_redirects=True, dict(
            username="",
            email="",
            password=""
        ))

```

### Environment to run application
* Python 3.8
* Flask
* Flask-Bootstrap
* Flask-SQLAlchemy
* Flask-Login
* Simplejson
* SQLite

### Install the pacakge and Run Application Command

```sh
$ pip install Flask
$ pip install Flask-bootstrap
$ pip install Flask-SQLalcheny
$ pip install Flask-Login
```
install SQ lite from https://www.sqlite.org/download.html

How to run website:
1) Save Project folder to Desktop on computer
2) Navigate to Project folder within terminal 
3) Run the following on Terminal:
```sh
$ python3 Cuisine.py
$ export FLASK_APP=Cuisine
$ export FLASK_ENV=development
$ flask run
```
4) Copy URL (http://127.0.0.1:5000) and paste into web browser


### The lesson learned from M1
* Since we have limited time to deliver M1, then we need to prioritize the user stories, break down the tasks and sub-tasks and distribute to team members. Then, we can focus on each task. We have tried to set up a standup meeting to brainstorm, update progression, and solve the problems.
* Calculating velocity and burn down chart: Since we have been fixed at 4 headcounts, we have adapted the sum of hours left VS sum of hours needed to calculate velocity and create burn down chart instead of the number of tasks left.
* Testing with pytest will help us to gain confidence in our software.
* Working in difference environments or systems settings, may makes some challenges such as running application, package installation.

***
## Milestone 2

### Velocity

There are 6 user stories and 13 Tasks in Milestone 2

| Task No. | Task | Days required | Hours required |
| ------ | ------ | ------ | ------ |
| **U1** | **I want to look for restaurants within Orange County. What kind of services do they provide (outdoor/indoor seating, take out, delivery, curbside, social distancing, and disinfecting and sanitizing). I want to find a restaurant that matches my criteria within Orange County** | **7**| M D
| 1a | Extract location information and names of restaurants from Twitter API. | 3 | 12 |
| 1b | Create queries for the different keywords(seating, take out, …). | 2 | 8 |
| 1c | Create interface for user/diner to search for services based on keywords(search bar,sub pages). | 2 | 8 | 
| **U2** | **As a diner, I want to find restaurants near me that are COVID compliant. How are restaurants maintaining a safe and COVID compliant environment?** | **3** | D
| 2a | Create additional queries, with keywords related to a restaurant being COVID compliant(from Twitter feed). | 2 | 8 |
| 2b | Design functionality for user to be able to set search radius on the map. | 1 | 4 |
| **U3** | **I want to see what others have said about certain restaurants.** | **3** | M
| 3a | Extract data from Yelp API, to get information/restaurant reviews from the other diners regarding the restaurants in diners’ queries. | 2 | 8 |
| 3b | Create window within program specificially for Yelp, to store reviews/information about restaurants as they become available. | 1 | 4 |
| **U4** | **I would like to see information on how restaurants have been impacted by COVID (How long have they been closed for? Are they currently open?)** | **6** | V T
| 4a | Pull data from Twitter API, posts from restaurants that talk about their open/closed status during pandemic. | 3 | 12 |
| 4b | Display relevant information(in clear and consistent manner for all restaurants) found in tweets in pop-up dialogue window when user selects a certain restaurant on the map. | 3 | 12 |
| **U5** | **How much seating is available at a given restaurant?** | **2** | V
| 5a | Pull information about seating/seating capacity percentage from restaurants’ twitter pages. | 1 | 4 |
| 5b | Allow for user to query just seating information when looking up a specific restaurant. | 1 | 4 |
| **U6** | **I would like to have the option to see restaurants that match my given criteria within a list.** | **2** | M D V T
| 6a | Create a separate results box within the program – show restaurants that match criteria user has given. | 1 | 4 |
| 6b | Sort results by which criteria item the user entered in first. | 1 | 4 |
| | Total | 23 | 92 |

Days needed = 23 days | Assume that 4 working hours per day | 4 developers --> 1 hour per team member per day
Velocity = Average Productivity = 80%

| Factors | Data | How to calculate |
| ------ | ------ | ------ |
| Sprint start date | 4-Nov | |
| Sprint end date | 5-Dec |  |
| Working days | 23 |  |
| Team size | 4 |  |
| Work hours per day | 1 |  |
| Total available hours | 92 | working days * team size * work hours per day |
| Average daily available hours | 4 | total available hours / working days |
| Average productivity | 80 % |  |
| Productivity hours | 73.6 | total available hours * average productivity |
| Average daily productive hours | 4 | productivity hours / working days |

### Burn Down Chart:
We have created the burn down calculator to input the working hours for each developer.
Please follow the link https://bit.ly/31q50o7
(Only CGU member with this link can access, but only our team can edit)

![N|Solid](https://i.ibb.co/TTf0pGd/Screen-Shot-2020-12-07-at-4-03-03-PM.png)
![N|Solid](https://i.ibb.co/S0Ph0FZ/Burndown-M2.png)

### Stand Up Meeting:
| Meeting No | Date | Detail |
| ------ | ------ | ------ |
| 1 | Nov 5 | Brainstorming, Allocated the user stories to specific developers |
| 2 | Nov 10 | Brainstorming, sharing the progression and figure out the errors |
| 3 | Nov 17 | Update the progression after meeting with professors |
| 4 | Nov 19 | Relocate the repo in git due to the technical problems |
| 5 | Nov 20 | Re-sync the repo across the team and update the progression |
| 6 | Nov 21 | Sharing the progression and brainstorming |
| 7 | Nov 30 | Sharing the progression |
| 8 | Dec 2 | Meeting with professor and solve the problems |
| 9 | Dec 3 | Sharing progression and pytest coverage |
| 10 | Dec 6 | Brainstorming the problems for possible solution |

### Test Code and coverage
Testing coverage 100%
* Test base
* Test register page
* Test login page
* Test my pregerence
* Test login

How to run pytest: (We have separated application which is included pytest into another file --> Cuisine_Test.py)
```sh
$ pytest -v Cuisine_Test.py
```
![N|Solid](https://i.ibb.co/k86zcPq/Pytest-Project-V2-Screenshot.png)
All functions pass.

How to check percentage coverage: 
```sh
$ pytest --cov=Users Cuisine_Test.py
```
![N|Solid](https://i.ibb.co/yyY9rn6/Pytest-Coverage.png)
100% Coverage.

### The lesson learned from M2
* Calculating velocity and burn down chart: Base on the M1, we have succeeded in using the proportion between the actual working hours burned and the expected hour burned. However, the M2 is different from the M1, which we need to wait for the response from the third-party who can provide permission to their services. Then, in the first half of M2, the actual working hour burned was lower than the forecast.
* This methodology can only use base on the assumptions: 
    1) All user stories have to be achieved at the end of the iteration
    2) All estimations have been forecasted precisely
* Testing with pytest will help us to gain confidence in our software.
* Working in different environments or systems settings may make some challenges such as running applications and package installation.
* If the software needห to connect to the third-party, we need to create plan B in case of unexpected situations that can cause a project delay.
