# JoggingTrackerAPIBackend

This repository contains a Django-Rest-Framework implementation of the back-end API of a jogging tracker app.

<p align="center">
  <img src="images/running.jpg">
</p>

## App requirements
* API Users must be able to create an account and log in.
* All API calls must be authenticated.
* Implement at least three roles with different permission levels: a regular user would only be able to CRUD on their owned records, a user manager would be able to CRUD only users, and an admin would be able to CRUD all records and users.
* Each time entry when entered has a date, distance, time, and location.
* Based on the provided date and location, API should connect to a weather API provider and get the weather conditions for the run, and store that with each run.
* The API must create a report on average speed & distance per week.
* The API must be able to return data in the JSON format.
* The API should provide filter capabilities for all endpoints that return a list of elements, as well should be able to support pagination.
* The API filtering should allow using parenthesis for defining operations precedence and use any combination of the available fields. The supported operations should at least include or, and, eq (equals), ne (not equals), gt (greater than), lt (lower than).
  Example -> (date eq '2016-05-01') AND ((distance gt 20) OR (distance lt 10)).
* Write unit and e2e tests.

## Running the code
1. Create the environment from the [conda file](environment.yml): `conda env create -f environment.yml`
2. Activate the conda environment: `conda activate toptal`
3. Check all the tests are runing: `python manage.py test api`
6. Run the server: `python manage.py runserver`. By default, the server link is `http://127.0.0.1:8000/`
7. There are 2 parent endpoints: `api/` and `admin`. `admin` is used in order to login with a superuser.
8. The `api` endpoint contains all the jogging application endpoints. They can be viewed [here](api/urls.py)

## User journey with Postman
1. Register by creating a `POST` request to `api/user` with body `{'first_name': 'user', 'last_name': 'user', 'email': 'user@user.com', 'password': 'user' , 'username': 'user'}
`
2. Get login authentication token by creating a `POST` request to `api/token-auth` with the body `{'password': 'user' , 'username': 'user'}`
3. Add the authentication token to Postman Headers: `Authorization` `Token <token_value>`
4. Create a Jog by sending a `POST` request to `api/jogs` with body `{'date': '2020-04-23', 'distance:' 50, 'time': 50 'location': 'Amsterdam', 'user_id': <your_user_id>}`. The weather will be filled automatically by the API.
5. Once you added multiple jogs, view your weekly report by sending a `GET` request to `api/weekly_report`. You can change the date by specifying the `date` parameter .

Enjoy!