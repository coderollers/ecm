package configuration

type CSwagger struct {
	Version     string `yaml:"version"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	BasePath    string `yaml:"basepath"`
}
