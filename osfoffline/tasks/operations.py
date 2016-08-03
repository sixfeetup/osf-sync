import abc
import http.client
import logging
import os
import shutil

from pathlib import Path

from osfoffline import settings
from osfoffline import utils
from osfoffline.client import osf as osf_client
from osfoffline.client.osf import OSFClient
from osfoffline.database import models
from osfoffline.database import Session
from osfoffline.tasks.notifications import Notification
from osfoffline.utils.authentication import get_current_user


logger = logging.getLogger(__name__)


def permission_error_notification(file_or_folder, file_name, node_title):
    Notification().error(
        'Could not sync {} {} in project {}. Please verify you '
        'have write permission to the project.'.format(file_or_folder, file_name, node_title)
    )

class OperationContext:
    """Store common data describing an operation"""
    def __init__(self, *, local=None, db=None, remote=None, node=None, is_folder=False, check_is_folder=True):
        self._db = db
        self._node = node
        self._local = local
        self._remote = remote
        self._is_folder = is_folder
        self._check_is_folder = check_is_folder
        # Platform-safe filename alias. False if unset, None (null) if no alias required
        self._alias = False

    def __repr__(self):
        return '<{}(node={}, local={}, db={}, remote={})>'.format(self.__class__.__name__, self._node, self._local, self._db, self._remote)

    @property
    def node(self):
        if self._node:
            return self._node

        if self._db:
            self._node = self._db.node
        elif self._local:
            self._node = utils.extract_node(str(self._local))
        elif self._remote:
            pass  # TODO run extract node

        return self._node

    @property
    def db(self):
        if self._db:
            return self._db
        if self._local:
            self._db = utils.local_to_db(
                self._local,
                self.node,
                is_folder=self._is_folder,
                check_is_folder=self._check_is_folder
            )
        elif self._remote:
            with Session() as session:
                self._db = session.query(models.File).filter(models.File.id == self._remote.id).one()
        return self._db

    @property
    def remote(self):
        if self._remote:
            return self._remote
        if self._db:
            self._remote = utils.db_to_remote(self.db)
        return self._remote

    @property
    def local(self):
        if self._local:
            return self._local
        if self._db:
            self._local = Path(self._db.path)
        return self._local

    @property
    def alias(self):
        """Remove platform-specific bad characters from the filename if needed. (requires remote data)
            The alias field should be stored as null in the DB if the filename does not need to be transformed,
            to minimize redundant data."""
        if self.remote.name == 'osfstorage':
            # If this event is for OSF Storage folder, no alias is required
            return None

        # Fetch parent object directly (will already exist even before self.db is defined, eg create events)
        db_parent = Session().query(models.File).filter(models.File.id == self.remote.parent.id).one()
        if self._alias is False:
            safe_name = utils.legal_filename(self.remote.name, parent=db_parent)
            if safe_name != self.remote.name:
                self._alias = safe_name
            else:
                self._alias = None
        return self._alias

    @property
    def safe_name(self):
        """Return the basename appropriate for local filesystem."""
        # TODO: Implement options if remote is undefined (eg using db safe_name property)
        return self.alias or self.remote.name


class BaseOperation(abc.ABC):

    def __init__(self, context):
        self._context = context

    @abc.abstractmethod
    def _run(self):
        """Internal implementation of run method; must be overridden in subclasses"""
        raise NotImplementedError

    def run(self, *, dry=False):
        """Wrap internal run method with logging, so that even nested jobs report individually"""
        logger.info('Starting {!r}'.format(self))
        if not dry:
            return self._run()
        logger.info('Job successfully completed')

    @property
    def db(self):
        return self._context.db

    @property
    def local(self):
        return self._context.local

    @property
    def remote(self):
        return self._context.remote

    @property
    def node(self):
        return self._context.node

    @property
    def alias(self):
        return self._context.alias

    @property
    def safe_name(self):
        return self._context.safe_name

    def __repr__(self):
        return '<{}({})>'.format(self.__class__.__name__, self._context)


class MoveOperation(BaseOperation):

    def __init__(self, context, dest_context):
        self._dest_context = dest_context
        super().__init__(context)

    def __repr__(self):
        return '<{}(from {} to {})>'.format(self.__class__.__name__, self._context, self._dest_context)


# Download File
class LocalCreateFile(BaseOperation):
    """Download an individual file from the OSF into a folder that already exists"""

    def _run(self):
        with Session() as session:
            db_parent = session.query(models.File).filter(models.File.id == self.remote.parent.id).one()
        path = os.path.join(db_parent.path, self.safe_name)
        # TODO: Create temp file in target directory while downloading, and rename when done. (check that no temp file exists)
        resp = OSFClient().request('GET', self.remote.raw['links']['download'], stream=True)
        with open(path, 'wb') as fobj:
            for chunk in resp.iter_content(chunk_size=1024 * 64):
                if chunk:
                    fobj.write(chunk)

        # After file is saved, create a new database object to track the file
        #   If the task fails, the database task will be kicked off separately by the auditor on a future cycle
        # TODO: Handle a filename being aliased in local storage (due to OS limitations)?
        DatabaseCreateFile(
            OperationContext(remote=self.remote, node=self.node)
        ).run()

        Notification().info('Downloaded File {} in {}'.format(self.db.pretty_path, self.node.title))


class LocalCreateFolder(BaseOperation):
    """Create a folder, and populate the contents of that folder (all files to be downloaded)"""

    def _run(self):
        with Session() as session:
            db_parent = session.query(models.File).filter(models.File.id == self.remote.parent.id).one()
        # TODO folder and file with same name
        os.mkdir(os.path.join(db_parent.path, self.safe_name))
        DatabaseCreateFolder(
            OperationContext(remote=self.remote, node=self.node)
        ).run()
        Notification().info('Downloaded Folder: {}'.format(self.db.pretty_path))


# Download File
class LocalUpdateFile(BaseOperation):
    """Download a file from the remote server and modify the database to show task completed"""

    def _run(self):
        with Session() as session:
            db_file = session.query(models.File).filter(models.File.id == self.remote.id).one()

        tmp_path = os.path.join(db_file.parent.path, '.~tmp.{}'.format(db_file.safe_name))

        resp = OSFClient().request('GET', self.remote.raw['links']['download'], stream=True)
        with open(tmp_path, 'wb') as fobj:
            for chunk in resp.iter_content(chunk_size=1024 * 64):
                if chunk:
                    fobj.write(chunk)
        shutil.move(tmp_path, db_file.path)

        DatabaseUpdateFile(
            OperationContext(db=db_file, remote=self.remote, node=db_file.node)
        ).run()
        Notification().info('Uploaded File {} to {}'.format(db_file.pretty_path, self.node.title))


class LocalDeleteFile(BaseOperation):

    def _run(self):
        self.local.unlink()
        DatabaseDeleteFile(
            OperationContext(db=utils.local_to_db(self.local, self.node))
        ).run()


class LocalDeleteFolder(BaseOperation):
    """Delete a folder (and all containing files) locally"""

    def _run(self):
        shutil.rmtree(str(self.local))
        DatabaseDeleteFolder(self._context).run()


class RemoteCreateFile(BaseOperation):
    """Upload a file to the OSF, and update the database to reflect the new OSF id"""

    def _run(self):
        if self.db is not None:
            # On windows, a file update operation can sometimes jump the queue ahead of a file create
            # due to how watchdog fires events
            logger.debug('File already exists; will run update operation instead')
            return RemoteUpdateFile(self._context).run()

        parent = utils.local_to_db(self.local.parent, self.node)

        url = '{}/v1/resources/{}/providers/{}/{}'.format(settings.FILE_BASE, self.node.id, parent.provider, parent.osf_path)
        with self.local.open(mode='rb') as fobj:
            resp = OSFClient().request('PUT', url, data=fobj, params={'name': self.local.name})
        data = resp.json()
        if resp.status_code == http.client.FORBIDDEN:
            permission_error_notification('file', self.local.name, self.node.title)
        else:
            assert resp.status_code == http.client.CREATED, '{}\n{}\n{}'.format(resp, url, data)

            remote = osf_client.File(None, data['data'])
            # WB id are <provider>/<id>
            remote.id = remote.id.replace(remote.provider + '/', '')
            remote.parent = parent

            DatabaseCreateFile(
                OperationContext(remote=remote, node=self.node)
            ).run()
            Notification().info('Uploaded New File: {} in {}'.format(self.db.pretty_path, self.node.title))


class RemoteCreateFolder(BaseOperation):
    """Upload a folder (and contents) to the OSF and create multiple DB instances to track changes"""

    def _run(self):
        parent = utils.local_to_db(self.local.parent, self.node)

        url = '{}/v1/resources/{}/providers/{}/{}'.format(settings.FILE_BASE, self.node.id, parent.provider, parent.osf_path)
        resp = OSFClient().request('PUT', url, params={'kind': 'folder', 'name': self.local.name})
        data = resp.json()
        if resp.status_code == http.client.FORBIDDEN:
            permission_error_notification('folder', self.local.name, self.node.title)
        else:
            assert resp.status_code == http.client.CREATED, '{}\n{}\n{}'.format(resp, url, data)

            remote = osf_client.File(None, data['data'])
            # WB id are <provider>/<id>/
            remote.id = remote.id.replace(remote.provider + '/', '').rstrip('/')
            remote.parent = parent

            DatabaseCreateFolder(
                OperationContext(remote=remote, node=self.node)
            ).run()
            Notification().info('Created Folder {} in {}'.format(self.db.pretty_path, self.node.title))


class RemoteUpdateFile(BaseOperation):
    """Upload (already-tracked) file to the OSF (uploads new version)"""

    def _run(self):
        if self.db is None:
            # TODO: Test edge case where file is created both locally and remotely with same name within a given sync window
            logger.debug('File not yet tracked; will run create operation instead')
            return RemoteCreateFile(self._context).run()

        url = '{}/v1/resources/{}/providers/{}/{}'.format(settings.FILE_BASE, self.node.id, self.db.provider, self.db.osf_path)
        with open(str(self.local), 'rb') as fobj:
            resp = OSFClient().request('PUT', url, data=fobj)
        data = resp.json()
        if resp.status_code == http.client.FORBIDDEN:
            permission_error_notification('file', self.local.name, self.node.title)
        else:
            assert resp.status_code in (http.client.OK, http.client.CREATED), '{}\n{}\n{}'.format(resp, url, data)

            remote = osf_client.File(None, data['data'])
            # WB id are <provider>/<id>
            remote.id = remote.id.replace(remote.provider + '/', '')
            remote.parent = self.db.parent
            DatabaseUpdateFile(
                OperationContext(remote=remote, db=self.db, node=self.node)
            ).run()
            Notification().info('Updated File {} in {}'.format(self.db.pretty_path, self.node.title))


class RemoteDelete(BaseOperation):
    """Delete a file or folder that is already known to exist remotely"""

    def _run(self):
        resp = OSFClient().request('DELETE', self.remote.raw['links']['delete'])
        with Session() as session:
            db_model = session.query(models.File).filter(models.File.id == self.remote.id).one()
        if resp.status_code == http.client.FORBIDDEN:
            permission_error_notification(db_model.kind.lower(), self.remote.name, self.node.title)
        else:
            assert resp.status_code == http.client.NO_CONTENT, resp
            Notification().info('Deleted {}: {} in {}'.format(db_model.kind.capitalize(), db_model.pretty_path, self.node.title))
        # Always delete the database record. There are two cases:
        # 1. User can write, and the remote file is deleted
        # 2. User can not write, but has deleted a local file. Forgetting the database record means that file
        # will get re-synced later
        DatabaseDelete(
            OperationContext(db=db_model)
        ).run()


# Auditor looks for operations by specific names; DRY redundant implementations
RemoteDeleteFile = RemoteDeleteFolder = RemoteDelete


class DatabaseCreateFile(BaseOperation):
    """Create a file in the database, based on information provided from the remote server,
        and attach the file to the specified node"""

    def _run(self):
        parent = self.remote.parent.id if self.remote.parent else None

        with Session() as session:
            session.add(models.File(
                id=self.remote.id,
                name=self.remote.name,
                alias=self.alias,
                kind=self.remote.kind,
                provider=self.remote.provider,
                user=get_current_user(),
                parent_id=parent,
                node_id=self.node.id,
                size=self.remote.size,
                md5=self.remote.extra['hashes']['md5'],
                sha256=self.remote.extra['hashes']['sha256'],
            ))
            session.commit()


class DatabaseCreateFolder(BaseOperation):

    def _run(self):
        parent = self.remote.parent.id if self.remote.parent else None

        with Session() as session:
            session.add(models.File(
                id=self.remote.id,
                name=self.remote.name,
                alias=self.alias,
                kind=self.remote.kind,
                provider=self.remote.provider,
                user=get_current_user(),
                parent_id=parent,
                node_id=self.node.id
            ))
            session.commit()


class DatabaseUpdateFile(BaseOperation):

    def _run(self):
        parent = self.remote.parent.id if self.remote.parent else None

        self.db.name = self.remote.name
        self.db.alias = self.alias
        self.db.kind = self.remote.kind
        self.db.provider = self.remote.provider
        self.db.user = get_current_user()
        self.db.parent_id = parent
        self.db.node_id = self.node.id
        self.db.size = self.remote.size
        self.db.md5 = self.remote.extra['hashes']['md5']
        self.db.sha256 = self.remote.extra['hashes']['sha256']

        with Session() as session:
            session.add(self.db)
            session.commit()


class DatabaseUpdateFolder(BaseOperation):

    def _run(self):
        parent = self.remote.parent.id if self.remote.parent else None

        self.db.name = self.remote.name
        self.db.alias = self.alias
        self.db.kind = self.remote.kind
        self.db.provider = self.remote.provider
        self.db.user = get_current_user()
        self.db.parent_id = parent
        self.db.node_id = self.node.id

        with Session() as session:
            session.add(self.db)
            session.commit()


class DatabaseDelete(BaseOperation):

    def _run(self):
        with Session() as session:
            session.delete(self.db)
            session.commit()


# Auditor looks for operations by specific names; DRY redundant implementations
DatabaseDeleteFolder = DatabaseDeleteFile = DatabaseDelete


class RemoteMove(MoveOperation):
    """Move an item on the OSF; subclass for file or folder variants"""

    DB_CLASS = None

    def _run(self):
        if self.db is None and self.remote is None:
            # If a file is an ignored name and get renamed to a not ignored name
            # it will trigger a move but not exist anywhere else
            logger.debug('Source file does not exist; will run create operation instead')
            return RemoteCreateFile(self._dest_context).run()

        dest_parent = OperationContext(local=self._dest_context.local.parent)
        resp = OSFClient().request('POST',
                                   self.remote.raw['links']['move'],
                                   json={
                                       'action': 'move',
                                       'path': dest_parent.db.osf_path if dest_parent.db.parent else '/',
                                       'rename': self._dest_context.local.name,
                                       'resource': self._dest_context.node.id,
                                   })

        data = resp.json()
        if resp.status_code == http.client.FORBIDDEN:
            permission_error_notification(
                'folder' if self._dest_context.local.is_dir else 'file',
                self._dest_context.local.name, self._dest_context.node.title
            )
            # Delete the database record.
            DatabaseDelete(
                OperationContext(db=self.db)
            ).run()
        else:
            assert resp.status_code in (http.client.CREATED, http.client.OK), resp

            remote = osf_client.File(None, data['data'])
            # WB id are <provider>/<id>
            remote.id = remote.id.replace(remote.provider + '/', '')
            with Session() as session:
                remote.parent = session.query(models.File).filter(models.File.id == dest_parent.db.id).one()
            self.DB_CLASS(
                OperationContext(remote=remote, db=self.db, node=remote.parent.node)
            ).run()


class RemoteMoveFolder(RemoteMove):
    DB_CLASS = DatabaseUpdateFolder


class RemoteMoveFile(RemoteMove):
    DB_CLASS = DatabaseUpdateFile


class LocalMove(MoveOperation):
    """
    Move a local item. Subclass for file or folder variants.
    """
    DB_CLASS = None

    def _run(self):
        # Construct a platform-safe path  alias (filename + parent folders),
        #  without aliasing the user or project part of the path
        db_parent = self._context.db.parent
        path_to_alias = self._dest_context.local.relative_to(db_parent.path_unaliased)
        safe_fn = utils.legal_filename(str(path_to_alias), parent=db_parent)
        safe_path = Path(db_parent.path).joinpath(safe_fn)

        shutil.move(str(self._context.db.path), str(safe_path))
        self.DB_CLASS(
            OperationContext(
                db=self._context.db,
                remote=self._dest_context.remote,
                node=self._dest_context.node)
        ).run()


class LocalMoveFile(LocalMove):
    DB_CLASS = DatabaseUpdateFile


class LocalMoveFolder(LocalMove):
    DB_CLASS = DatabaseUpdateFolder
