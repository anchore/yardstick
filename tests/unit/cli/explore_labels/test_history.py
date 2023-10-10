import pytest
from yardstick.cli.explore.image_labels.history import Command, History


@pytest.fixture()
def counter_command_state():
    items = []

    def redo(count):
        def do():
            print("adding", count, "to", items)
            items.append(count)

        return do

    def undo(count):
        def do():
            print("removing", count, "from", items)
            items.remove(count)

        return do

    return undo, redo, items


@pytest.fixture()
def history_of_5(counter_command_state):
    undo, redo, state = counter_command_state
    history = History()

    for i in range(5):
        history.record(Command(undo=undo(i), redo=redo(i)))
    return history, undo, redo, state


def test_history_record(history_of_5):
    history, undo, redo, state = history_of_5
    assert state == [0, 1, 2, 3, 4]


def test_history_undo(history_of_5):
    history, undo, redo, state = history_of_5
    # first undo...
    history.undo()
    assert state == [0, 1, 2, 3]

    # second undo...
    history.undo()
    assert state == [0, 1, 2]

    # undo until empty...
    history.undo()
    history.undo()
    history.undo()
    assert state == []

    # check we don't go path the boundary
    history.undo()
    assert state == []


def test_history_redo(history_of_5):
    history, undo, redo, state = history_of_5
    # prep undo...
    history.undo()
    history.undo()
    history.undo()
    assert state == [0, 1]

    # first redo...
    history.redo()
    assert state == [0, 1, 2]

    # redo all...
    history.redo()
    history.redo()
    assert state == [0, 1, 2, 3, 4]

    # check we don't go path the boundary
    history.redo()
    assert state == [0, 1, 2, 3, 4]


def test_history_undo_redo_rewrite(history_of_5):
    history, undo, redo, state = history_of_5
    # prep undo...
    history.undo()
    history.undo()
    history.undo()
    assert state == [0, 1]

    # first redo...
    history.redo()
    assert state == [0, 1, 2]

    # record new history
    history.record(Command(undo=undo(42), redo=redo(42)))

    assert state == [0, 1, 2, 42]

    # redo does nothing...
    history.redo()
    history.redo()
    assert state == [0, 1, 2, 42]

    # undo still works
    history.undo()
    history.undo()
    assert state == [0, 1]

    # a few more cases...
    history.record(Command(undo=undo(72), redo=redo(72)))

    assert state == [0, 1, 72]

    history.undo()
    history.undo()
    history.undo()
    history.undo()
    assert state == []

    history.redo()
    history.redo()
    history.redo()
    history.redo()
    history.redo()
    history.redo()
    history.redo()

    assert state == [0, 1, 72]
