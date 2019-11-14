import json
import dbconnection
import random


class DBHelper:
    db = dbconnection.Database(dbconnection.Config())
    korean_vendor = ['SamsungE', 'SamsungT', 'LgInform', 'LGLElect', 'LgElectr', 'LgInnote']

    def _query_result_to_dict(self, query_result):
        ret = json.loads(json.dumps(query_result[0][0]))
        ret = json.loads(ret)
        ret = [json.loads(x.replace('\'', '\"')) for x in ret]

        return ret

    def _get_latest_radio_data(self, device_type):
        query = 'SELECT {} FROM radio_info_tbl ORDER BY id DESC LIMIT 1'.format(device_type)

        try:
            row = self.db.exec_query(query)
            data = self._query_result_to_dict(row)
            return data

        except Exception as e:
            print(e)
            return None

    def _get_num_of_radio(self, device_type):
        data = self._get_latest_radio_data(device_type)
        return 0 if not data else len(data)

    def _get_average_rssi(self, device_type):
        data_list = self._get_latest_radio_data(device_type)
        ret = 0

        for data in data_list:
            ret += data['RSSI']

        return 0 if ret == 0 else int(ret / len(data_list))

    def _get_vendor_ratio(self, device_type):
        data_list = self._get_latest_radio_data(device_type)

        num_of_korean_vendor = 0

        for data in data_list:
            if data['vendor'] in self.korean_vendor:
                num_of_korean_vendor += 1

        korean_vendor_ratio = round(num_of_korean_vendor / len(data_list), 2)
        other_vendor_ratio = 1 - korean_vendor_ratio

        return korean_vendor_ratio - other_vendor_ratio

    def get_num_of_visitors(self):
        query = 'SELECT {} FROM radio_info_tbl ORDER BY id DESC LIMIT 1'.format('num_of_visitors')

        try:
            row = self.db.exec_query(query)
            return row[0][0]

        except Exception as e:
            print(e)
            return None

    def get_wi_fi_rssi_avg(self):
        return self._get_average_rssi('wi_fi')

    def get_num_of_wi_fi_dev(self):
        return self._get_num_of_radio('wi_fi')

    def get_wi_fi_vendor_ratio(self):
        return self._get_vendor_ratio('wi_fi')

    def get_ble_rssi_avg(self):
        return self._get_average_rssi('ble')

    def get_num_of_ble_dev(self):
        return self._get_num_of_radio('ble')

    def get_ble_vendor_ratio(self):
        return self._get_vendor_ratio('ble')

    def get_wi_fi_notes(self):
        data_list = self._get_latest_radio_data('wi_fi')
        ret = []
        for data in data_list:
            ret.append(-int(data['RSSI']))

        random.seed(self.get_wi_fi_rssi_avg())

        if len(ret) < 10:
            missing = 10 - len(ret)
            ret.extend([random.randrange(40, 80) for x in range(missing)])
        elif len(ret) > 10:
            ret = ret[:10]

        return ret
