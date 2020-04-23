import requests

class WeatherAPI:

    API_KEY  = '1cad47e768cd6377195152f2e19bdf64'
    API_LINK = 'http://api.weatherstack.com/current'

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key else self.API_KEY

    def get_weather(self, location , date):
        params = {
            'access_key': self.api_key,
            'query': location,
            'historical_date': date
        }

        api_result = requests.get(self.API_LINK, params)
        api_response = api_result.json()
        weather_description = api_response['current']['weather_descriptions'][0]

        return weather_description

if __name__ == "__main__":
    api = WeatherAPI()
    api.get_weather(location='Amsterdam', date='2020/04/23')
