import pytest

import os
from pathlib import Path

from watchdog import events

from osfoffline import utils
from osfoffline.tasks import operations
from osfoffline.utils.log import start_logging
from osfoffline.sync.utils import EventConsolidator

from tests.sync.utils import TestSyncObserver


start_logging()


_map = {
    ('move', True): events.DirMovedEvent,
    ('move', False): events.FileMovedEvent,
    ('modify', True): events.DirModifiedEvent,
    ('modify', False): events.FileModifiedEvent,
    ('delete', True): events.DirDeletedEvent,
    ('delete', False): events.FileDeletedEvent,
    ('create', True): events.DirCreatedEvent,
    ('create', False): events.FileCreatedEvent,
}


def Event(type_, *src, sha=None):
    assert len(src) < 3
    if len(src) > 1:
        assert src[0].endswith('/') == src[1].endswith('/')
    event = _map[(type_, src[0].endswith('/'))](*(x.rstrip('/').replace('/', os.path.sep) for x in src))
    event.sha256 = sha
    return event


CASES = [{
    'input': [
        Event('move', '/untitled/', '/newfolder/'),
        Event('move', '/donut002.txt', '/newfolder/donut002.txt'),
    ],
    'output': [
        Event('move', '/untitled/', '/newfolder/'),
        Event('move', '/donut002.txt', '/newfolder/donut002.txt'),
    ]
}]


# List of tests that can't be easily parsed by the integration tester
UNIT_ONLY = []


TMP_CASES = []


CONTEXT_EVENT_MAP = {
    events.FileCreatedEvent: operations.RemoteCreateFile,
    events.FileDeletedEvent: operations.RemoteDeleteFile,
    events.FileModifiedEvent: operations.RemoteUpdateFile,
    events.FileMovedEvent: operations.RemoteMoveFile,
    events.DirCreatedEvent: operations.RemoteCreateFolder,
    events.DirDeletedEvent: operations.RemoteDeleteFolder,
    events.DirMovedEvent: operations.RemoteMoveFolder,
}






class TestObserver:

    def perform(self, tmpdir, event):
        if isinstance(event, events.FileModifiedEvent):
            with tmpdir.join(event.src_path).open('ab') as fobj:
                fobj.write(event.sha256 or os.urandom(50))
        elif isinstance(event, events.FileCreatedEvent):
            with tmpdir.join(event.src_path).open('wb+') as fobj:
                fobj.write(event.sha256 or os.urandom(50))
        elif isinstance(event, events.DirModifiedEvent):
            return
        elif isinstance(event, (events.FileMovedEvent, events.DirMovedEvent)):
            tmpdir.join(event.src_path).move(tmpdir.join(event.dest_path))
        elif isinstance(event, (events.DirDeletedEvent, events.FileDeletedEvent)):
            tmpdir.join(event.src_path).remove()
        elif isinstance(event, events.DirCreatedEvent):
            tmpdir.ensure(event.src_path, dir=True)
        else:
            raise Exception(event)

    @pytest.mark.parametrize('input, expected', [(case['input'], case['output']) for case in CASES])
    def test_event_observer(self, monkeypatch, tmpdir, input, expected):
        og_input = tuple(input)
        def local_to_db(local, node, *, is_folder=False, check_is_folder=True):
            found = False
            for event in reversed(og_input):
                if str(tmpdir.join(getattr(event, 'dest_path', ''))) == str(local):
                    return local_to_db(tmpdir.join(event.src_path), None)

                if str(tmpdir.join(event.src_path)) == str(local):
                    found = event
                    if event.event_type == events.EVENT_TYPE_CREATED:
                        return False

            # Doesnt really matter, just needs to be truthy and have a sha256
            return found

        def sha256_from_event(event):
            for evt in og_input:
                if str(event.src_path) in (str(tmpdir.join(evt.src_path)), str(tmpdir.join(getattr(evt, 'dest_path', evt.src_path)))):
                    event.is_directory = evt.is_directory  # Hack to make tests pass on windows. Delete events are emitted as file deletes. Other code compensates for this
                    if evt.sha256:
                        return evt.sha256

            if event.event_type == events.EVENT_TYPE_DELETED:
                return None

            try:
                return utils.hash_file(Path(getattr(event, 'dest_path', event.src_path)))
            except (IsADirectoryError, PermissionError):
                return None

        monkeypatch.setattr('osfoffline.sync.local.utils.extract_node', lambda *args, **kwargs: None)
        monkeypatch.setattr('osfoffline.sync.local.utils.local_to_db', local_to_db)
        monkeypatch.setattr('osfoffline.sync.ext.watchdog.settings.EVENT_DEBOUNCE', 2)
        monkeypatch.setattr('osfoffline.sync.ext.watchdog.sha256_from_event', sha256_from_event)

        # De dup input events
        for event in tuple(input):
            for evt in tuple(input):
                if event is not evt and not isinstance(event, events.DirModifiedEvent) and event.event_type != events.EVENT_TYPE_CREATED and evt.event_type == event.event_type and evt.src_path.startswith(event.src_path) and (event.event_type != events.EVENT_TYPE_MOVED or evt.dest_path.startswith(event.dest_path)):
                    input.remove(evt)

        for event in reversed(input):
            path = tmpdir.ensure(event.src_path, dir=event.is_directory)
            if not event.is_directory:
                with path.open('wb+') as fobj:
                    fobj.write(os.urandom(50))

            if isinstance(event, (events.FileMovedEvent, events.DirMovedEvent)):
                tmpdir.ensure(event.dest_path, dir=event.is_directory).remove()

            if isinstance(event, (events.FileCreatedEvent, events.DirCreatedEvent)):
                path.remove()

        observer = TestSyncObserver(tmpdir.strpath, 1)
        # Clear cached instance of Observer
        del type(TestSyncObserver)._instances[TestSyncObserver]

        observer.start()
        assert observer.is_alive()

        # Wait until watchdog is actually reporting events
        retries = 0
        path = tmpdir.ensure('plstonotuse')
        with path.open('w') as fobj:
            while True:
                fobj.write('Testing...\n')
                fobj.flush()
                if observer.done.wait(3):
                    break
                retries += 1
                if retries > 4:
                    raise Exception('Could not start observer')

        observer.flush()
        observer.expected = 1
        observer._events = []
        observer.done.clear()

        path.remove()
        observer.done.wait(5)

        # Reset the observer to its inital state
        observer.flush()
        observer.expected = len(expected)
        observer._events = []
        observer.done.clear()

        import pdb; pdb.set_trace()
        for event in input:
            self.perform(tmpdir, event)

        observer.done.wait(3)
        observer.stop()
        observer.flush()

        assert len(expected) == len(observer._events)

        for event, context in zip(expected, observer._events):
            assert CONTEXT_EVENT_MAP[type(event)] == type(context)
            assert str(tmpdir.join(event.src_path)) == str(context.local)
