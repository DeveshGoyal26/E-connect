import React, { useState } from "react";
import axios from "axios";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { useNavigate } from "react-router-dom";

const Signup = () => {
  const [form, setForm] = useState({});
  const [isLogin, setIsLogin] = useState({});
  const notify = (msg) => toast(msg);
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState("password");

  const signupHandler = async (e) => {
    e.preventDefault();

    if (form.password !== form.confirmPassword) {
      return notify(
        "password && confirm password not matching please check again"
      );
    }

    if (!form.email || !form.password || !form.username) {
      return notify("please provide username  & password && email");
    }
    if (form.password.length < 6) {
      return notify("password will be minimum 6 charcters");
    }

    try {
      const data = await axios.post(
        "https://e-connect-app.herokuapp.com/signup",
        form,
        {
          credentials: "include",
          withCredentials: true,
        }
      );

      setIsLogin(data.data);
      notify("login successfull");
      navigate("/");
    } catch (e) {
      console.log(e);
      notify(e.response.data.error);
    }
  };

  return (
    <div>
      <div className="bg-white dark:bg-gray-900">
        <div className="flex justify-center h-screen">
          <div
            className="hidden bg-cover lg:block lg:w-2/3"
            style={{
              backgroundImage:
                "url(https://images.unsplash.com/photo-1588702547919-26089e690ecc?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80)",
            }}
          >
            <div className="flex items-center h-full px-20 bg-gray-900 bg-opacity-40">
              <div>
                <h2 className="text-4xl font-bold text-white">E-connect</h2>

                <p className="max-w-xl mt-3 text-gray-300">
                  E-connect is a platform where you can meet people and learn
                  together Signup and Connect with People who is like you
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center w-full max-w-md px-6 mx-auto lg:w-2/6">
            <div className="flex-1">
              <div className="text-center">
                <h2 className="text-4xl font-bold text-center text-gray-700 dark:text-white">
                  E-connect
                </h2>

                <p className="mt-3 text-gray-500 dark:text-gray-300">
                  Signup and Create new account
                </p>
              </div>

              <div className="mt-8">
                <form onSubmit={(e) => signupHandler(e)}>
                  <div>
                    <label
                      htmlFor="email"
                      className="block mb-2 text-sm text-gray-600 dark:text-gray-200"
                    >
                      Username
                    </label>
                    <input
                      type="text"
                      name="username"
                      id="username"
                      onChange={(e) =>
                        setForm({ ...form, [e.target.name]: e.target.value })
                      }
                      placeholder="John123"
                      className="block w-full px-4 py-2 mt-2 text-gray-700 placeholder-gray-400 bg-white border border-gray-200 rounded-md dark:placeholder-gray-600 dark:bg-gray-900 dark:text-gray-300 dark:border-gray-700 focus:border-blue-400 dark:focus:border-blue-400 focus:ring-blue-400 focus:outline-none focus:ring focus:ring-opacity-40"
                    />
                  </div>
                  <div className="mt-6">
                    <label
                      htmlFor="email"
                      className="block mb-2 text-sm text-gray-600 dark:text-gray-200"
                    >
                      Email Address
                    </label>
                    <input
                      type="email"
                      name="email"
                      id="email"
                      onChange={(e) =>
                        setForm({ ...form, [e.target.name]: e.target.value })
                      }
                      placeholder="example@example.com"
                      className="block w-full px-4 py-2 mt-2 text-gray-700 placeholder-gray-400 bg-white border border-gray-200 rounded-md dark:placeholder-gray-600 dark:bg-gray-900 dark:text-gray-300 dark:border-gray-700 focus:border-blue-400 dark:focus:border-blue-400 focus:ring-blue-400 focus:outline-none focus:ring focus:ring-opacity-40"
                    />
                  </div>

                  <div className="mt-6">
                    <div className="flex justify-between mb-2">
                      <label
                        htmlFor="password"
                        className="text-sm text-gray-600 dark:text-gray-200"
                      >
                        Password
                      </label>
                    </div>

                    <div className="flex items-center ">
                      <input
                        type={showPassword}
                        name="password"
                        id="password"
                        onChange={(e) =>
                          setForm({ ...form, [e.target.name]: e.target.value })
                        }
                        placeholder="Your Password"
                        className="block w-full px-4 py-2 mt-2 text-gray-700 placeholder-gray-400 bg-white border border-gray-200 rounded-md dark:placeholder-gray-600 dark:bg-gray-900 dark:text-gray-300 dark:border-gray-700 focus:border-blue-400 dark:focus:border-blue-400 focus:ring-blue-400 focus:outline-none focus:ring focus:ring-opacity-40"
                      />
                      {showPassword == "password" ? (
                        <i
                          className="fa-solid fa-eye -ml-8 mt-2 cursor-pointer"
                          onClick={() =>
                            setShowPassword((prev) =>
                              prev == "password" ? "text" : "password"
                            )
                          }
                        ></i>
                      ) : (
                        <i
                          className="fa-solid fa-eye-slash -ml-8 mt-2 cursor-pointer"
                          onClick={() =>
                            setShowPassword((prev) =>
                              prev == "password" ? "text" : "password"
                            )
                          }
                        ></i>
                      )}
                    </div>
                  </div>
                  <div className="mt-6">
                    <div className="flex justify-between mb-2">
                      <label
                        htmlFor="password"
                        className="text-sm text-gray-600 dark:text-gray-200"
                      >
                        Confirm Password
                      </label>
                    </div>

                    <input
                      type="password"
                      name="confirmPassword"
                      id="confirmpassword"
                      onChange={(e) =>
                        setForm({ ...form, [e.target.name]: e.target.value })
                      }
                      placeholder="Confirm Your Password"
                      className="block w-full px-4 py-2 mt-2 text-gray-700 placeholder-gray-400 bg-white border border-gray-200 rounded-md dark:placeholder-gray-600 dark:bg-gray-900 dark:text-gray-300 dark:border-gray-700 focus:border-blue-400 dark:focus:border-blue-400 focus:ring-blue-400 focus:outline-none focus:ring focus:ring-opacity-40"
                    />
                  </div>

                  <div className="mt-6">
                    <button className="w-full px-4 py-2 tracking-wide text-white transition-colors duration-200 transform bg-blue-500 rounded-md hover:bg-blue-400 focus:outline-none focus:bg-blue-400 focus:ring focus:ring-blue-300 focus:ring-opacity-50">
                      Signup
                    </button>
                  </div>
                </form>

                <p className="mt-6 text-sm text-center text-gray-400">
                  Already have an account ?{" "}
                  <button
                    onClick={() => navigate("/login")}
                    className="text-blue-500 focus:outline-none focus:underline hover:underline"
                  >
                    Sign in
                  </button>
                  .
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
      <ToastContainer />
    </div>
  );
};

export default Signup;
