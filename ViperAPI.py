import requests
from collections import defaultdict

class ViperAPIClient(object):
    DEFAULT_HOST = 'http://192.168.1.61'
    DEFAULT_PORT = 9090
    DEFUALT_TOKEN = '9a7499a80a44ff52fce4ba0254ba017780729bba'
    LIST_ALL_NOTES = '/api/v3/project/{project_name}/note/'
    LIST_ALL_PROJECTS = '/api/v3/project/'

    def __init__(self, host=None, port=None, token=None, project=None):
        self.host = host or self.DEFAULT_HOST
        self.port = port or self.DEFAULT_PORT
        self.token = token or self.DEFUALT_TOKEN
        self.project = project or 'default'

        self._session = requests.session()
        # self._session.auth = 
        # pass

    def _get_response(self, url, params=None):
        res = self._session.get(url, params=params or {}, 
            headers={'Accept': 'application/json', 'Authorization':f'Token {self.token}'})
        if res.status_code != 200:
            raise Exception(res.reason)
        return res

    def _post_response(self, url, params=None, data=None):
        res = self._session.post(url, params=params or {}, data=data or {},
            headers={'Accept': 'application/json', 'Authorization':f'Token {self.token}'})
        if res.status_code != 200:
            raise Exception(res.reason)
        return res

    def _put_response(self, url, params=None, data=None):
        res = self._session.put(url, params=params or {}, data=data or {},
            headers={'Accept': 'application/json', 'Authorization':f'Token {self.token}'})
        if res.status_code != 200:
            raise Exception(res.reason)
        return res

    def _get_url(self, endpoint):
        pass

    def get_projectMalware(self):
        url = f'{self.host}:{self.port}{self.LIST_ALL_PROJECTS}{self.project}/malware'
        print(url)
        while True:
            if url == None:
                break
            json_obj = self._get_response(url).json()
            for result in json_obj['results']:
                yield result
            if 'next' in json_obj.keys():
                url = json_obj['next']
            else:
                break

    def get_project(self):
        url = f'{self.host}:{self.port}{self.LIST_ALL_PROJECTS}{self.project}/'
        print(url)
        while True:
            json_obj = self._get_response(url).json()
            for result in json_obj['results']:
                yield result
            if 'next' in json_obj.keys():
                url = json_obj['next']
            else:
                break

    def get_projects(self):
        url = f'{self.host}:{self.port}{self.LIST_ALL_PROJECTS}'
        print(url)
        while True:
            json_obj = self._get_response(url).json()
            for result in json_obj['results']:
                yield result
            if 'next' in json_obj.keys():
                url = json_obj['next']
            else:
                break
    
    def get_notes(self, project):
        url = f'{self.host}:{self.port}/api/v3/project/{project}/note/'
        while url is not None:
            json_obj = self._get_response(url).json()
            for result in json_obj['results']:
                yield {
                    'body': result['data']['body'],
                    'title' : result['data']['title'],
                    'id' : result['data']['id'],
                    'name' : result['data']['malware_set'][0]['data']['name'],
                }
            if 'next' in json_obj.keys():
                url = json_obj['next']
            else:
                break
    
    
    def get_note(self, project, sha256):
        url = f'{self.host}:{self.port}/api/v3/project/{project}/malware/{sha256}/note/'
        print(url)
        while True:
            if url == None:
                break
            json_obj = self._get_response(url).json()
            for result in json_obj['results']:
                yield result
            if 'next' in json_obj.keys():
                url = json_obj['next']
            else:
                break


    def create_note(self, project, sha256, title, body):
        url = f'/api/v3/project/{project}/malware/{sha256}/note/'
        data = {
            'title' : title,
            'body' : body
        }
        res = self._post_response(url, data=data)
        return res

    def update_note(self, project, sha256, title, body, id):
        url = f'/api/v3/project/{project}/note/{id}/'
        data = {
            'title' : title,
            'body' : body
        }
        res = self._put_response(url, data=data)
        return res

if __name__ == "__main__":
    viper = ViperAPIClient(project='kerberos') #litmus_1216
    # for project in viper.get_projects():
    #     print(project)
    notes = defaultdict(list)
    for note in viper.get_notes('kerberos'):
        sha256 = note['name']

        notes[sha256].append(note)
        # print(note)

    for key, value in notes.items():
        print(f'{key} : {value}')

    

