// Copyright 2014 beego Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config is used to parse config
// Usage:
// import(
//   "github.com/astaxie/beego/config"
// )
//
//  cnf, err := config.NewConfig("ini", "config.conf")
//
//  cnf APIS:
//
//  cnf.Set(key, val string) error
//  cnf.String(key string) string
//  cnf.Strings(key string) []string
//  cnf.Int(key string) (int, error)
//  cnf.Int64(key string) (int64, error)
//  cnf.Bool(key string) (bool, error)
//  cnf.Float(key string) (float64, error)
//  cnf.DefaultString(key string, defaultVal string) string
//  cnf.DefaultStrings(key string, defaultVal []string) []string
//  cnf.DefaultInt(key string, defaultVal int) int
//  cnf.DefaultInt64(key string, defaultVal int64) int64
//  cnf.DefaultBool(key string, defaultVal bool) bool
//  cnf.DefaultFloat(key string, defaultVal float64) float64
//  cnf.DIY(key string) (interface{}, error)
//  cnf.GetSection(section string) (map[string]string, error)
//  cnf.SaveConfigFile(filename string) error
//
//  more docs http://beego.me/docs/module/config.md
package config

import (
	"fmt"
)

//定义了如何从原始的配置文件获得或者设置值
type Configer interface {
	Set(key, val string) error   //support section::key type in given key when using ini type.
	String(key string) string    //support section::key type in key string when using ini and json type; Int,Int64,Bool,Float,DIY are same.
	Strings(key string) []string //get string slice
	Int(key string) (int, error)
	Int64(key string) (int64, error)
	Bool(key string) (bool, error)
	Float(key string) (float64, error)
	DefaultString(key string, defaultVal string) string      // support section::key type in key string when using ini and json type; Int,Int64,Bool,Float,DIY are same.
	DefaultStrings(key string, defaultVal []string) []string //get string slice
	DefaultInt(key string, defaultVal int) int
	DefaultInt64(key string, defaultVal int64) int64
	DefaultBool(key string, defaultVal bool) bool
	DefaultFloat(key string, defaultVal float64) float64
	DIY(key string) (interface{}, error)
	GetSection(section string) (map[string]string, error)
	SaveConfigFile(filename string) error
}

// Config is the adapter interface for parsing config file to get raw data to Configer.
type Config interface {
	Parse(key string) (Configer, error)
	ParseData(data []byte) (Configer, error)
}
/*
 * 在整个 config包中,这个全局变量是最先被创建的。
 * 然后才是不同源文件的 init()函数执行,同一个包内不同源文件的 init()执行顺序与包名从小到大的排列顺序相同
 * adapters 用于根据名字分类保存不同的配置器
 *
 * 包内的数据逻辑:
 *	通过获取 Config类型的不同配置器(,注意同配置器在对应包内的 init()函数内注册到了 adapters中,
 *  	并且实现了 Parse() ParseData()),调用实现了的接口可以获得不同配置器的 ConfigContainer对象(该
 * 	对象实现了 config.go内的 Configer接口所提供的方法)。从而可以供 beego.config.go文件中的
 *	beegoAppConfig实例进行获取配置
 */
var adapters = make(map[string]Config)

// Register makes a config adapter available by the adapter name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
// 提供给不同配置器注册到 adapters变量中的方法
func Register(name string, adapter Config) {
	if adapter == nil {
		panic("config: Register adapter is nil")
	}
	if _, ok := adapters[name]; ok {
		panic("config: Register called twice for adapter " + name)
	}
	adapters[name] = adapter
}

// NewConfig adapterName is ini/json/xml/yaml.
// filename is the config file path.
// 传入配置器的名称和配置文件的路径名
// 通过调用配置器的 adapter.Parse() 返回一个 不同包内的 ConfigContainer类型。
// 包内的 ConfigContainer也实现了 Configer接口所定义的不同配置类型的获取
func NewConfig(adapterName, filename string) (Configer, error) {
	adapter, ok := adapters[adapterName]
	if !ok {
		return nil, fmt.Errorf("config: unknown adaptername %q (forgotten import?)", adapterName)
	}
	return adapter.Parse(filename)
}

// NewConfigData adapterName is ini/json/xml/yaml.
// data is the config data.
/*
 * 传入配置器的名称和配置的数据,在解析完传入的数据后获得配置文件路径,然后在 ParseData()方法内调用 Parse()获得 ConfigContainer实例
 */
func NewConfigData(adapterName string, data []byte) (Configer, error) {
	adapter, ok := adapters[adapterName]
	if !ok {
		return nil, fmt.Errorf("config: unknown adaptername %q (forgotten import?)", adapterName)
	}
	return adapter.ParseData(data)
}

// ParseBool returns the boolean value represented by the string.
//
// It accepts 1, 1.0, t, T, TRUE, true, True, YES, yes, Yes,Y, y, ON, on, On,
// 0, 0.0, f, F, FALSE, false, False, NO, no, No, N,n, OFF, off, Off.
// Any other value returns an error.
// 根据传入的变量判断该配置项的值是否应该解析成 Bool类型
func ParseBool(val interface{}) (value bool, err error) {
	if val != nil {
		switch v := val.(type) {
		case bool:
			return v, nil
		case string:
			switch v {
			case "1", "t", "T", "true", "TRUE", "True", "YES", "yes", "Yes", "Y", "y", "ON", "on", "On":
				return true, nil
			case "0", "f", "F", "false", "FALSE", "False", "NO", "no", "No", "N", "n", "OFF", "off", "Off":
				return false, nil
			}
		case int8, int32, int64:
			strV := fmt.Sprintf("%s", v)
			if strV == "1" {
				return true, nil
			} else if strV == "0" {
				return false, nil
			}
		case float64:
			if v == 1 {
				return true, nil
			} else if v == 0 {
				return false, nil
			}
		}
		return false, fmt.Errorf("parsing %q: invalid syntax", val)
	}
	return false, fmt.Errorf("parsing <nil>: invalid syntax")
}
