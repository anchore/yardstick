from dataclasses import dataclass
from typing import Callable, List


@dataclass
class Command:
    undo: Callable
    redo: Callable


class History:
    history: List[Command]
    index: int

    def __init__(self):
        self.history = []
        self.index = 0

    def record(self, command: Command):
        # clear any history after the current index, but only if the index has moved (we've done undo's since the last record)
        if self.index + 1 != len(self.history):
            self.history = self.history[: self.index]
        # record the new event
        self.history.append(command)
        self.redo()  # perform the action for the first time

    def undo(self):
        if self.index > 0:
            self.index -= 1
            self.history[self.index].undo()

    def redo(self):
        if self.index <= len(self.history) - 1:
            self.history[self.index].redo()
            self.index += 1

    def total_events(self):
        return len(self.history)

    def undone_events(self):
        return len(self.history) - (self.index)

    def reset(self):
        self.history = []
        self.index = 0
