import csv
import ViperAPI
from pathlib import Path
from ViperAPI import ViperAPIClient
from collections import defaultdict

class ST_Sample_Diff():
    sha256           : str = ""
    note_result_A    : str = ""
    note_detection_A : str = ""
    note_result_B    : str = ""
    note_detection_B : str = ""

if __name__ == "__main__":
    projectName = 'public'
    viper = ViperAPIClient(project=projectName) #'test_kerberos'

    samples = defaultdict(list)

# listup sha256
    for cur_malwares in viper.get_projectMalware():
        stsample = ST_Sample_Diff()
        stsample.sha256 = cur_malwares['data']['sha256']

        for note in viper.get_note(projectName, stsample.sha256):
            if note['data']['title'] == 'Result':
                stsample.note_result_A = note['data']['body']
            if note['data']['title'] == 'Detections':
                stsample.note_detection_A = note['data']['body']
        '''#project / malware / 하위의 data > note_set 은 상황에 따라 들어오지 않는 데이터
        for note in cur_malwares['data']['note_set']:
            if note['data']['title'] == 'Result':
                stsample.note_result_A = note['data']['body']
            if note['data']['title'] == 'Detections':
                stsample.note_detection_A = note['data']['body']
        '''
        samples[stsample.sha256] = stsample
#A - notes
#B
    for note in viper.get_notes(projectName):
        sha256 = note['name']
        
        if note['title'] == 'Result':
            samples[sha256].note_result_B = note['body']
        if note['title'] == 'Detections':
            samples[sha256].note_detection_B = note['body']
#C



    for key, value in samples.items():
        print(f'{key} : {value.note_result_A},{value.note_detection_A},{value.note_result_B},{value.note_detection_B},')

    #to csv
    with open('notes_Gets.csv', 'w', newline='') as csvfile:
        fieldnames = ['sha256', 'resultA', 'detectionA', 'resultB', 'detectionB']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        
        for key, value in samples.items():
            writer.writerow({'sha256': value.sha256, 'resultA': value.note_result_A, 'detectionA': value.note_detection_A, 'resultB': value.note_result_B, 'detectionB': value.note_detection_B})
'''
    #방법 A
    for note in viper.get_project():
        sha256 = note['name']

        notes[sha256].append(note)
        # print(note)

    for key, value in notes.items():
        print(f'{key} : {value}')
        '''