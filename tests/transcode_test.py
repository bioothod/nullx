import argparse
import elliptics
import json
import mmap
import requests

class ttest:
    def __init__(self, input, addr):
        self.input = input
        self.output = '/tmp/transcoding_test.out'
        self.addr = addr
        self.file = open(input, 'r')

        self.elog = None
        self.node = None

        self.init_elliptics(None, None, None, None)
        self.init_elliptics_metadata(None, None, None, None)

    def filedata(self):
        return mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)

    def init_elliptics(self, groups, ebucket, ekey, eid):
        self.ekey = ekey
        self.ebucket = ebucket
        self.eid = eid
        self.egroups = groups

    def init_elliptics_metadata(self, mgroups, mbucket, mkey, mid):
        self.mkey = mkey
        self.mbucket = mbucket
        self.mid = mid
        self.mgroups = mgroups

    def init_node(self, log_file, log_level, remotes):
        if not self.node:
            self.elog = elliptics.Logger(log_file, log_level)
            self.node = elliptics.Node(self.elog)
            self.node.add_remotes(remotes)

    def transcode_download(self):
        h = {}
        r = requests.post(self.addr, data=self.filedata(), headers=h, stream=True)
        if r.status_code != 200:
            print 'transcoding failed, status: %d' % (r.status_code)
            raise AssertionError('transcoding failed, status: %d' % (r.status_code))

        print("received status: %d", r.status_code)
        chunk_size = 1024 * 1024
        output_size = 0
        with open(self.output, 'wb') as out:
            for chunk in r.iter_content(chunk_size):
                out.write(chunk)
                output_size += len(chunk)

        print "transcoded file %s -> %s, transcoded size: %d" % (self.input, self.output, output_size)

    def elliptics_session(self, groups, bucket):
        session = elliptics.Session(self.node)
        session.set_groups(groups)

        if bucket:
            session.set_namespace(bucket)

        return session

    def elliptics_remove(self, groups, bucket, key, id):
        session = self.elliptics_session(groups, bucket)

        if key:
            try:
                session.remove(key).wait()
            except Exception as e:
                print('could not remove key \'%s\', error: %s' % (key, e))

        if id:
            eid = elliptics.Id.from_hex(id)
            try:
                session.remove(eid).wait()
            except Exception as e:
                print('could not remove id \'%s\', error: %s' % (id, e))


    def elliptics_cleanup(self):
        if self.egroups:
            self.elliptics_remove(self.egroups, self.ebucket, self.ekey, self.eid)
        if self.mgroups:
            self.elliptics_remove(self.mgroups, self.mbucket, self.mkey, self.mid)

    def check_read(self, groups, bucket, key, id):
        session = self.elliptics_session(groups, bucket)

        if key:
            session.read_data(key, 0, 0).wait()

        if id:
            eid = elliptics.Id.from_hex(id)
            session.read_data(eid, 0, 0).wait()

    def send_and_check(self, h, groups, bucket, key, id):
        r = requests.post(self.addr, data=self.filedata(), headers=h)
        if r.status_code != 200:
            print('headers: %s, status: %d' % (h, r.status_code))
            raise AssertionError('check failed, headers: %s, status: %d' % (h, r.status_code))

        js = r.json()

        self.check_read(groups, bucket, key, id)

    def transcode_elliptics_upload(self):
        self.elliptics_cleanup()

        if self.ekey:
            h = {}
            h['X-Ell-Key'] = self.ekey
            h['X-Ell-Bucket'] = self.ebucket
            h['X-Ell-Groups'] = ':'.join([str(i) for i in self.egroups])

            self.send_and_check(h, self.egroups, self.ebucket, self.ekey, None)
            print("successfully tested transcoded file upload into %s/%s" % (self.ebucket, self.ekey))

        if self.eid:
            h = {}
            h['X-Ell-ID'] = self.eid
            h['X-Ell-Groups'] = ':'.join([str(i) for i in self.egroups])

            self.send_and_check(h, self.egroups, None, None, self.eid)
            print("successfully tested transcoded file upload into %s" % (self.eid))

    def transcode_elliptics_upload_metadata(self):
        self.elliptics_cleanup()

        if self.ekey and self.mkey:
            h = {}
            h['X-Ell-Key'] = self.ekey
            h['X-Ell-Bucket'] = self.ebucket
            h['X-Ell-Groups'] = ':'.join([str(i) for i in self.egroups])
            h['X-Ell-Metadata-Key'] = self.mkey
            h['X-Ell-Metadata-Bucket'] = self.mbucket
            h['X-Ell-Metadata-Groups'] = ':'.join([str(i) for i in self.mgroups])

            self.send_and_check(h, self.mgroups, self.mbucket, self.mkey, None)
            print("successfully tested metadata upload from transcoded file into %s/%s" % (self.mbucket, self.mkey))

        if self.eid and self.mid:
            h = {}
            h['X-Ell-ID'] = self.eid
            h['X-Ell-Groups'] = ':'.join([str(i) for i in self.egroups])
            h['X-Ell-Metadata-ID'] = self.mid
            h['X-Ell-Metadata-Groups'] = ':'.join([str(i) for i in self.mgroups])

            self.send_and_check(h, self.mgroups, None, None, self.mid)
            print("successfully tested metadata upload from transcoded file into %s" % (self.mid))

if __name__ == '__main__':
    tparser = argparse.ArgumentParser(add_help=False)
    tparser.add_argument('--input', dest='input', action='store', required=True, help='Input file to transcode')
    tparser.add_argument('--addr', dest='addr', action='store', required=True,
            help='Address of the transcoding server including schema and path, for example http://localhost:8080/upload/')

    tparser.add_argument('--groups', dest='groups', action='store', help='Save transcoded file into these groups, format: 1:2:3')
    tparser.add_argument('--bucket', dest='bucket', action='store', help='Put transcoded file into this elliptics bucket (namespace)')
    tparser.add_argument('--key', dest='key', action='store', help='Key used to upload transcoded file into elliptics')
    tparser.add_argument('--id', dest='id', action='store', help='ID used to upload transcoded file into elliptics')

    tparser.add_argument('--meta-groups', dest='meta_groups', action='store',
            help='Save metadata from transcoded file into these groups, format: 1:2:3')
    tparser.add_argument('--meta-bucket', dest='meta_bucket', action='store',
            help='Put metadata from transcoded file into this elliptics bucket (namespace)')
    tparser.add_argument('--meta-key', dest='meta_key', action='store',
            help='Key used to upload metadata from transcoded file into elliptics')
    tparser.add_argument('--meta-id', dest='meta_id', action='store',
            help='ID used to upload metadata from transcoded file into elliptics')

    eparser = argparse.ArgumentParser(description='Elliptics arguments.', add_help=False)
    eparser.add_argument('--remote', dest='remotes', action='append', help='Remote elliptics nodes, format: addr:port:family')
    eparser.add_argument('--log-file', dest='log_file', action='store', default='/dev/stdout',
            help='Elliptics log file, default: %default')
    eparser.add_argument('--log-level', dest='log_level', action='store', default=3,
            help='Elliptics log level, default: %default')

    parser = argparse.ArgumentParser(description='Transcoding test', parents=[tparser, eparser])

    args = parser.parse_args()

    if not args.input:
        print("You must specify input file to transcode")
        exit(-1)
    if not args.addr:
        print("You must specify address of the transcoding server")
        exit(-1)

    try:
        t = ttest(args.input, args.addr)
        #t.transcode_download()

        if args.groups or args.meta_groups:
            if not args.remotes:
                print("To run elliptics test you must specify remote nodes")
                exit(-1)

            t.init_node(args.log_file, args.log_level, args.remotes)

            if args.groups:
                groups = [int(x) for x in args.groups.split(':')]

                if args.key or args.id:
                    t.init_elliptics(groups, args.bucket, args.key, args.id)
                    t.transcode_elliptics_upload()

            if args.meta_groups:
                groups = [int(x) for x in args.meta_groups.split(':')]

                if args.meta_key or args.meta_id:
                    t.init_elliptics_metadata(groups, args.meta_bucket, args.meta_key, args.meta_id)
                    t.transcode_elliptics_upload_metadata()
    except Exception as e:
        print("Transcoding test failed, exception: %s" % (e))
        raise
