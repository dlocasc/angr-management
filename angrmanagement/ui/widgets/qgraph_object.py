from PySide2.QtWidgets import QGraphicsItem


class QCachedGraphicsItem(QGraphicsItem):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self._cached_bounding_rect = None
        self._cached_device_pixel_ratio = None

    def clear_cache(self):
        self.prepareGeometryChange()
        self._cached_bounding_rect = None
        self._cached_device_pixel_ratio = None

    def refresh(self):
        pass

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    def recalculate_size(self):
        self.prepareGeometryChange()
        self._cached_device_pixel_ratio = None
        self._cached_bounding_rect = self._boundingRect()

    def boundingRect(self):
        if self._cached_bounding_rect is None:
            self._cached_bounding_rect = self._boundingRect()
        return self._cached_bounding_rect

    def _boundingRect(self):
        raise NotImplementedError()

    def _boundingRectAdjusted(self):
        # adjust according to devicePixelRatioF
        return self._boundingRect()


class QGraphObject:
    def __init__(self):

        self._x = None
        self._y = None
        self._width = None
        self._height = None

    @property
    def x(self):
        return self._x

    @x.setter
    def x(self, v):
        self._x = v

    @property
    def y(self):
        return self._y

    @y.setter
    def y(self, v):
        self._y = v

    @property
    def width(self):
        return self._width

    @property
    def height(self):
        return self._height

    def refresh(self):
        self._width, self._height = None, None

    def pos(self):
        """

        :return:
        """

        return self.x, self.y

    def size(self):
        """

        :return:
        """

        return self.width, self.height

    def paint(self, painter: 'QPainter'):
        """

        :param painter: The painter object.
        :return:                 None
        """

        raise NotImplementedError()

    def on_mouse_pressed(self, button, pos):
        """

        :param button:
        :param pos:
        :return:
        """
        pass

    def on_mouse_released(self, button, pos):

        pass

    def on_mouse_doubleclicked(self, button, pos):

        pass
