import hashlib
import os
import re
import sys

from sqlalchemy.orm.exc import NoResultFound

from osfoffline import settings
from osfoffline.database import Session
from osfoffline.database import models
from osfoffline.exceptions import NodeNotFound
from osfoffline.utils.authentication import get_current_user


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


def hash_file(path, *, chunk_size=65536):
    """
    Return the SHA256 hash of a file

    :param pathlib.Path path:
    :param int chunk_size: Read chunk size, in bytes
    :return:
    """
    s = hashlib.sha256()
    with path.open(mode='rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            s.update(chunk)
    return s.hexdigest()


def legal_filename(basename, parent=None):
    """
    Replace all OS-illegal characters in a filename with underscore, and return a new fn guaranteed to be unique
        in that folder https://support.microsoft.com/en-us/kb/177506
    :param str basename: The basename of a file, without path (eg 'is this a file and/or blob?.txt')
    :param models.File parent: If provided, will verify that the new aliased name is unique in the
        parent folder (or project osf storage folder). Two aliased names should not collide.
    :return:
    """
    # TODO: After we handle filenames, explore whether project names can also have illegal characters
    # TODO: Add a unit test!
    if sys.platform in ('win32', 'cygwin'):
        illegal_chars = r'\/:*?"<>|'
        new_fn = re.sub(r'[{}]'.format(illegal_chars), '_', basename)
        n = 1
        while parent:
            # If parent node is provided, loop through until a valid filename (not in use) is available
            if Session().query(models.File.name).filter(models.File.alias == new_fn,
                                                        models.File.parent == parent).all():
                fn, ext_and_sep = os.path.splitext(new_fn)
                new_fn = ''.join([fn, ' ({})'.format(n), ext_and_sep])
                n += 1
            else:
                # If no filename collision detected, break loop and return value
                break
        return new_fn
    else:
        # If not windows, just let the filename pass as-is for now
        return basename


def extract_node(path):
    """Given a file path extract the node id and return the loaded Database object
    Visual, how this method works:
        '/root/OSF/Node - 1244/Components/Node - 1482/OSF Storage/OSF Storage/OSF Storage/file.txt'
        '/OSF/Node - 1244/Components/Node - 1482/OSF Storage/OSF Storage/OSF Storage/file.txt'
        ['/OSF/Node - 1244/Components/Node - 1482/', '', '', '/file.txt']
        '/OSF/Node - 1244/Components/Node - 1482/'
        ['Node - 1244', 'Components', 'Node - 1482']
        'Node - 1482'
        1482
    """
    node_id = path.replace(get_current_user().folder, '').split(settings.OSF_STORAGE_FOLDER)[0].strip(os.path.sep).split(os.path.sep)[-1].split(' - ')[-1]
    try:
        return Session().query(models.Node).filter(models.Node.id == node_id).one()
    except NoResultFound:
        raise NodeNotFound(path)


def local_to_db(local, node, *, is_folder=False, check_is_folder=True):
    db = Session().query(models.File).filter(models.File.parent == None, models.File.node == node).one()  # noqa
    parts = str(local).replace(node.path, '').split(os.path.sep)
    for part in parts:
        for child in db.children:
            if child.name == part:
                db = child
    if db.path.rstrip(os.path.sep) != str(local).rstrip(os.path.sep) or (check_is_folder and db.is_folder != (local.is_dir() or is_folder)):
        return None
    return db


def db_to_remote(db):
    # Fix circular import
    from osfoffline.client import osf

    if db.parent is None:
        return _remote_root(db)
    return osf.StorageObject.load(osf.OSFClient().request_session, db.id)


def _remote_root(db):
    # Fix circular import
    from osfoffline.client import osf
    return next(
        storage
        for storage in
        osf.NodeStorage.load(osf.OSFClient().request_session, db.node.id)
        if storage.provider == db.provider
    )
