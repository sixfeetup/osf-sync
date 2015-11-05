import os
import requests
import json
import shutil

from invoke import task, run
from osfoffline.polling_osf_manager.remote_objects import RemoteNode
from osfoffline.polling_osf_manager.api_url_builder import api_url_for, NODES, USERS
from tests.fixtures.mock_osf_api_server.osf import app
from osfoffline.settings import DB_FILE_PATH

# WHEELHOUSE_PATH = os.environ.get('WHEELHOUSE')


# @task
# def wheelhouse(develop=False):
#     req_file = 'dev-requirements.txt' if develop else 'requirements.txt'
#     cmd = 'pip wheel --find-links={} -r {} --wheel-dir={}'.format(WHEELHOUSE_PATH, req_file, WHEELHOUSE_PATH)
#     run(cmd, pty=True)


# @task
# def install(develop=False, upgrade=False):
#     run('python setup.py develop')
#     req_file = 'dev-requirements.txt' if develop else 'requirements.txt'
#     cmd = 'pip install -r {}'.format(req_file)
#
#     if upgrade:
#         cmd += ' --upgrade'
#     if WHEELHOUSE_PATH:
#         cmd += ' --no-index --find-links={}'.format(WHEELHOUSE_PATH)
#     run(cmd, pty=True)


@task
def flake():
    run('flake8 . --config=./setup.cfg', pty=True)


# @task
# def test(verbose=False):
#     flake()
#     cmd = 'py.test --cov-report term-missing --cov waterbutler tests'
#     if verbose:
#         cmd += ' -v'
#     run(cmd, pty=True)


@task
def start():
    from start import start
    start()


@task
def start_for_tests():
    if os.path.exists(DB_FILE_PATH):
        os.remove(DB_FILE_PATH)

    OSF_DIR = '~/Desktop/OSF'
    if os.path.exists(OSF_DIR):
        shutil.rmtree(OSF_DIR)

    start()


@task
def mock_osf_api_server():
    app.run(debug=True)  # debug=None because we do not want auto restart


@task
def clean_mock_osf_api_server():
    path = './tests/fixtures/mock_osf_api_server/db_dir/mock_osf_api.db'
    if os.path.exists(path):
        os.remove(path)


@task
def create_test_user():
    ret = requests.post(
        api_url_for(USERS),
        data={
            'fullname': "new_test_user"
        })
    assert ret.status_code == 200
    to_print = 'test user created. Open OSF-Offline to start testing. Use the following credentials:' \
               '\nEmail: {email}' \
               '\nPassword: {password}'.format(
        email=ret.json()['data']['id'],
        password=ret.json()['data']['id']
    )
    print(to_print)
    return ret.json()['data']['id']


@task
def create_new_project(user_id):
    body = {
        "data": {
            "type": "nodes",  # required
            "attributes": {
                "title": 'new_test_project',  # required
                "category": 'Project',  # required
            }
        }
    }
    headers = {}
    headers['Authorization'] = 'Bearer {}'.format(user_id)
    headers['Content-Type'] = 'application/json'
    headers['Accept'] = 'application/json'
    ret = requests.post(api_url_for(NODES), data=json.dumps(body), headers=headers)
    print('new_test_project created for user {}'.format(user_id))
    return RemoteNode(ret.json()['data']).id


@task
def create_test_data():
    user_id = create_test_user()
    node_id = create_new_project(user_id)


@task
def start_mock_server():
    clean_mock_osf_api_server()
    mock_osf_api_server()
