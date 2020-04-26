import requests

class WeatherAPI:
    """Class used to connect to a weather API for retrieving the weather for a given location and date"""

    API_KEY  = '7b53fb539b6033de928e5045b0630e0d'
    API_LINK = 'http://api.weatherstack.com/current'

    def __init__(self, api_key=None):
        """
        Initializes the Weather API

        Args:
             api_key (str): key to connect to the api
        """
        self.api_key = api_key if api_key else self.API_KEY

    def get_weather(self, location , date):
        """
        Runs a request through the weather API and returns the weather at the location on the given date

        Args:
            location (str): location in which we want to see the weather status
            date (str "d-m-Y"): date for which we want to see the weather status

        Returns:
            string: Either "Unknown" in case there was an API error or the weather description returned by the API
        """
        params = {
            'access_key': self.api_key,
            'query': location,
            'historical_date': date
        }

        api_result = requests.get(self.API_LINK, params)
        api_response = api_result.json()

        if not 'current' not in api_response.keys():
            return 'Unknown'

        weather_description = api_response['current']['weather_descriptions'][0]

        return weather_description

if __name__ == "__main__":
    api = WeatherAPI()
    api.get_weather(location='Amsterdam', date='2020/04/23')
