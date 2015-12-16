class TransportAnalyzer(object):
    def __init__(self, interface):
        self.interface = interface

    def trace_read(self, data, **kwargs):
        return

    def trace_write(self, data, **kwargs):
        return

    @classmethod
    def attach(analyzer, interface_obj=None):
        if isinstance(analyzer, type):
            # create an instance of the appropriate analyzer class if this is
            # simply a type
            analyzer = analyzer(interface_obj)

        def read_wrapper(read_func):
            def trace_read(**kwargs):
                data = read_func(**kwargs)
                analyzer.trace_read(data, **kwargs)
                return data
            return trace_read

        def write_wrapper(write_func):
            def trace_write(data, **kwargs):
                analyzer.trace_write(data, **kwargs)
                return write_func(data, **kwargs)
            return trace_write

        interface_obj.read = read_wrapper(interface_obj.read)
        interface_obj.write = write_wrapper(interface_obj.write)
