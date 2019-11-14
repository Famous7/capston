import json


class RadioInfoList:
    def __init__(self):
        self._info_list = []

    def to_dict(self):
        if not self._info_list:
            return {}
        return self._info_list[len(self._info_list) - 1].to_dict()

    def _add_info(self, info):
        ref, idx = self.get_info(info.seq)

        if ref:
            return

        self._info_list.append(info)

    def get_info(self, seq):
        for i in range(len(self._info_list)):
            if self._info_list[i].seq == seq:
                return self._info_list[i], i

        return None, -1

    def add_data(self, seq, monitor_type, result):
        info, _ = self.get_info(seq)
        if not info:
            self._add_info(RadioInfo(seq=seq))
            info, _ = self.get_info(seq)

        info.set_data(monitor_type, result)

    def is_end(self, seq):
        info, _ = self.get_info(seq)
        if not info:
            return False

        return info.is_end()

    def remove_unreceived(self, idx):
        for i in range(idx):
            del self._info_list[i]

    def remove(self, seq):
        _, idx = self.get_info(seq)

        if idx == -1:
            return

        self.remove_unreceived(idx)
        # del self._info_list[idx]

    def get_query(self, seq):
        info, idx = self.get_info(seq)

        if not info:
            return None, None

        return info.make_query()


class RadioInfo:
    WI_FI_TYPE = 'WI-FI'
    BLE_TYPE = 'BLE'
    CAM_TYPE = 'CAM'

    def __init__(self, seq, wi_fi=None, ble=None, cam=None):
        self.seq = seq
        self._data = {RadioInfo.WI_FI_TYPE: wi_fi,
                      RadioInfo.BLE_TYPE: ble,
                      RadioInfo.CAM_TYPE: cam}

    def to_dict(self):
        return {'seq': self.seq, 'data': self._data}

    def get_data(self, monitor_type):
        if monitor_type not in (RadioInfo.WI_FI_TYPE, RadioInfo.BLE_TYPE, RadioInfo.CAM_TYPE):
            raise ValueError('Invalid monitor type: ' + monitor_type)
        return self._data[monitor_type]

    def set_data(self, monitor_type, data):
        if monitor_type not in (RadioInfo.WI_FI_TYPE, RadioInfo.BLE_TYPE, RadioInfo.CAM_TYPE):
            raise ValueError('Invalid monitor type: ' + monitor_type)
        self._data[monitor_type] = data

    def is_end(self):
        return None not in self._data.values()

    def make_query(self):
        sql = 'INSERT INTO radio_info_tbl(create_time, wi_fi, ble, num_of_visitors) VALUES(now(), %s, %s, %s)'
        args = (json.dumps(self.get_data(RadioInfo.WI_FI_TYPE)),
                json.dumps(self.get_data(RadioInfo.BLE_TYPE)),
                json.dumps(self.get_data(RadioInfo.CAM_TYPE)))

        return sql, args