---
layout: post
title: "I wrote a book (in Spanish) called Cronicas del Red Team"
date: 2026-06-14 10:00:00
categories: posts
en: true
description: Announcement of my book Cronicas del Red Team
keywords: "Red Team, Hacking"
authors:
    - X-C3LL
---


_(I wrote a book in Spanish, so this post will be in Spanish. You can use any translator from Spanish to English if you don't want to miss it. Or just use it to test your Duolingo skills)_

Hace diez años me mudé a Galicia para trabajar en un Red Team. El tiempo vuela, y de un pestañeo me doy cuenta que ya ha pasado una década. Diez años en los que he estado dedicado única y exclusivamente a hacer ejercicios de Red Team. He tocado todos los palos: estuve en primera línea de batalla siendo operador; después caté el amargor de los puestos de leader y manager; y por último retorné a ser un tranquilo operador que sólo tiene que preocuparse de sus propios proyectos. 

En los últimos años hablando con amigos y ex-compañeros de curro surgió el tema de que sería buena idea escribir un libro relatando operaciones de Red Team anonimizadas, con toda la realidad que hay detrás. Así que, después de sopesarlo durante meses con diferentes personas, decidí lanzarme a escribir un libro cortito a modo de recopilatorio de estos últimos años para que coincidiera con mi décido aniversario en estas lides. En principio iba a ser simplemente un obsequio para aquellas personas que, de una forma u otra, me han apoyado o coincidido conmigo durante estos años. Sin embargo, me han acabado convenciendo de que mejor hiciera bien las cosas y lo pusiera a la venta porque es un tema interesante y a otras personas le puede servir.

Así que eso es __Crónicas del Red Team__. Una recopilación de unas cuantas operaciones de Red Team, anonimizadas, que relato con ciertos tintes autobiográficos para contextualizarlas. La mayoría de capítulos pertenecen a etapas cronológicas diferentes y distribuidas aleatoriamente, por lo que puede leerse sin seguir ningún orden. 

<img src="/assets/img/book.jpg" alt="Crónicas del Red Team" />

En este libro no se habla de qué es un Red Team, ni se cuentan Técnicas o Tácticas novedosas (todo lo que aparece está ya quemado y no se usa en la actualidad). No se abordan claves organizativas ni cómo saltarte un EDR en 2026. No. Este libro es una simple recopilación de operaciones pasadas, donde efectivamente se explican cuestiones técnicas pero no es ni mucho menos el núcleo. Puede servir para ver cómo los TTPs han ido evolucionando durante esta década, cómo la cosas eran antes y cómo han ido cambiando con los años. Una dendrocronología donde lo que prima es contar cómo se hacían las cosas en el contexto en el que se ejecutó cada operación. 

Honestamente, creo que es café para los muy cafeteros y este tipo de contenido es demasiado nicho y sólo le interesará a las personas que estuvieron ahí cuando ejecutamos esas operaciones. Lo pondré a la venta oficialmente en unas semanas (ya avisaré por redes sociales), pero si alguien quiere una copia llevaré unos cuantos a este EuskalHack 2026.

Dejo debajo un extracto del libro para mostrar por donde van los tiros:

``` 
(...)
Los EDR, si bien suponían un grandísimo avance en la detección y telemetría, aun estaban en un estadio demasiado temprano y todavía no usaban kernel callbacks ni otros métodos más avanzados de detección. Prácticamente, en términos de volcado de memoria, únicamente hookeaban las funciones relacionadas con la generación de minidumps. En general esto era fácilmente evadible haciendo unhooking de los parches que se añadían para rastrear las llamadas o haciendo direct syscalling. En nuestro caso, optamos por la segunda opción y modificamos una prueba de concepto pública para convertirla en una DLL.

Usando las credenciales de administrador local, y la herramienta smbexec de Impacket, iniciamos sesión en otro equipo y ejecutamos nuestra DLL con rundll32.exe. En el volcado de memoria encontramos las credenciales del usuario objetivo, pero no de su cuenta "adm". Repetimos la operación en un par de qeuipos más y mismo resultado: solo obteníamos las credenciales de los usuarios "no privilegiados", pero ni rastro de las cuentas de Administrador de Dominio.

Cuando esto ocurre es generalmente porque el personal de TI opera desde máquinas de salto bastionadas y se autentican únicamente desde allí. Después de nuestro encontronazo con el EDR nos preocupaba irrumpir directamente en el servidor de bastionado pues lo mismo hacíamos saltar de nuevo las alarmas. Decidimos desplegar un keylogger en los equipos de los empleados de TI a los que ya habíamos accedido previamente.

El keylogger era bastante elegante. En vez de usar las funciones más típicas, ya que nos daba miedo que estuvieran intervenidas por el EDR, usaba NTUserGetRawInputData (exportada por win32u.dll). Además lo disfrazamos como si fuera un componente oficial del propio EDR: icono, metadatos, etc. Para la persistencia del mismo se creó una tarea programada en los equipos que, a su vez, tenía un nombre que aparentaba ser parte del EDR.

A los pocos días cazamos las credenciales de una cuenta "adm" y con ello nuestro primer objetivo estaba cumplido.
(...)

```






