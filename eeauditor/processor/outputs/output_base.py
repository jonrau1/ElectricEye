class ElectricEyeOutput(object):
    """Class to be used as a decorator to register all output providers"""

    _outputs = {}

    def __new__(cls, output):
        ElectricEyeOutput._outputs[output.__provider__] = output
        return output

    @classmethod
    def get_provider(cls, provider):
        """Returns the class to process the findings"""
        try:
            return cls._outputs[provider]
        except KeyError:
            print(f"Designated output provider {provider} does not exist")

    @classmethod
    def get_all_providers(cls):
        """Return a list of all the possible output providers"""
        return [*cls._outputs]
